cmake_minimum_required(VERSION 3.16)

project(altprobe VERSION 1.0.2 LANGUAGES CXX)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

include(CTest)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS thread iostreams regex)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GRPC REQUIRED IMPORTED_TARGET grpc++)
pkg_check_modules(PROTOBUF_PC REQUIRED IMPORTED_TARGET protobuf)

find_program(PROTOC_EXECUTABLE NAMES protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE NAMES grpc_cpp_plugin REQUIRED)

find_path(HIREDIS_INCLUDE_DIR NAMES hiredis/hiredis.h REQUIRED)
find_path(HIREDIS_LEGACY_INCLUDE_DIR NAMES hiredis.h PATH_SUFFIXES hiredis REQUIRED)
find_library(HIREDIS_LIBRARY NAMES hiredis REQUIRED)

find_path(DAEMON_INCLUDE_DIR NAMES libdaemon/daemon.h REQUIRED)
find_library(DAEMON_LIBRARY NAMES daemon REQUIRED)

find_path(MODSECURITY_INCLUDE_DIR NAMES modsecurity/modsecurity.h REQUIRED)
find_path(MODSECURITY_LEGACY_INCLUDE_DIR NAMES modsecurity.h PATH_SUFFIXES modsecurity REQUIRED)
find_library(MODSECURITY_LIBRARY NAMES modsecurity REQUIRED)

if(TARGET yaml-cpp::yaml-cpp)
    set(YAML_TARGET yaml-cpp::yaml-cpp)
elseif(TARGET yaml-cpp)
    set(YAML_TARGET yaml-cpp)
else()
    set(YAML_TARGET ${YAML_CPP_LIBRARIES})
endif()

add_subdirectory(shared)

set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN_DIR})

set(ALTPROBE_SOURCES
    trace_config.cpp
    trace_delivery.cpp
    otlp.cpp
    otlp_receiver.cpp
    classify.cpp
    cobject.cpp
    collector_config.cpp
    correlator.cpp
    detection.cpp
    filter.cpp
    llm_guard.cpp
    helpers.cpp
    incident.cpp
    inventory.cpp
    logs.cpp
    mitre.cpp
    ids_source.cpp
    openshell.cpp
    suricata.cpp
    eve.cpp
    modsec.cpp
    proxy.cpp
    scanner.cpp
    sinks.cpp
    source.cpp
    trace.cpp
)

set(OTLP_PROTOS
    opentelemetry/proto/common/v1/common.proto
    opentelemetry/proto/resource/v1/resource.proto
    opentelemetry/proto/trace/v1/trace.proto
    opentelemetry/proto/collector/trace/v1/trace_service.proto)
set(OTLP_SOURCES)
foreach(proto IN LISTS OTLP_PROTOS)
    string(REPLACE ".proto" ".pb.cc" source ${proto})
    string(REPLACE ".proto" ".pb.h" header ${proto})
    add_custom_command(OUTPUT ${GEN_DIR}/${source} ${GEN_DIR}/${header}
        COMMAND ${PROTOC_EXECUTABLE} -I ${PROTO_DIR} --cpp_out=${GEN_DIR} ${PROTO_DIR}/${proto}
        DEPENDS ${PROTO_DIR}/${proto} VERBATIM)
    list(APPEND OTLP_SOURCES ${GEN_DIR}/${source} ${GEN_DIR}/${header})
endforeach()
set(OTLP_SERVICE opentelemetry/proto/collector/trace/v1/trace_service)
add_custom_command(OUTPUT ${GEN_DIR}/${OTLP_SERVICE}.grpc.pb.cc ${GEN_DIR}/${OTLP_SERVICE}.grpc.pb.h
    COMMAND ${PROTOC_EXECUTABLE} -I ${PROTO_DIR} --grpc_out=${GEN_DIR}
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE} ${PROTO_DIR}/${OTLP_SERVICE}.proto
    DEPENDS ${PROTO_DIR}/${OTLP_SERVICE}.proto VERBATIM)
add_library(altprobe_core STATIC ${ALTPROBE_SOURCES} ${OTLP_SOURCES}
    ${GEN_DIR}/${OTLP_SERVICE}.grpc.pb.cc ${GEN_DIR}/${OTLP_SERVICE}.grpc.pb.h)

target_include_directories(altprobe_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${GEN_DIR}
        ${Boost_INCLUDE_DIRS}
        ${HIREDIS_INCLUDE_DIR}
        ${HIREDIS_LEGACY_INCLUDE_DIR}
        ${DAEMON_INCLUDE_DIR}
        ${MODSECURITY_INCLUDE_DIR}
        ${MODSECURITY_LEGACY_INCLUDE_DIR}
)

target_compile_definitions(altprobe_core
    PUBLIC
        BIG_JOINS=1
        _REENTRANT
        BOOST_BIND_GLOBAL_PLACEHOLDERS
)

target_compile_options(altprobe_core
    PRIVATE
        -fno-strict-aliasing
        -Wno-write-strings
        -Wno-deprecated
)

target_link_libraries(altprobe_core
    PUBLIC
        probe_shared
        Boost::thread
        Boost::iostreams
        Boost::regex
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        Threads::Threads
        PkgConfig::GRPC
        PkgConfig::PROTOBUF_PC
        ${YAML_TARGET}
        ${HIREDIS_LIBRARY}
        ${DAEMON_LIBRARY}
        ${MODSECURITY_LIBRARY}
        ${CMAKE_DL_LIBS}
        m
        rt
)

add_executable(altprobe main.cpp)
target_link_libraries(altprobe PRIVATE altprobe_core)

enable_testing()

set(PROBE_TEST_DRIVERS
    test_collector_config
    test_feature_window
    test_llm_guard
    test_http_deadlines
    test_incident_operation
    test_inventory_decode
    test_log_ack
    test_modsec_identity
    test_normalization
    test_source_lifecycle
    test_product_controls
    test_proxy_file
    test_trace_delivery)

if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  foreach(driver IN LISTS PROBE_TEST_DRIVERS)
    add_executable(${driver} tests/${driver}.cpp)
    target_link_libraries(${driver} PRIVATE altprobe_core)
    target_compile_options(${driver} PRIVATE -UNDEBUG)
    add_test(NAME ${driver} COMMAND ${driver})
    set_tests_properties(${driver} PROPERTIES TIMEOUT 60)
  endforeach()
  add_test(NAME test_proxy_runtime COMMAND ${Python3_EXECUTABLE} -B
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_proxy_runtime.py $<TARGET_FILE:altprobe>)
  set_tests_properties(test_proxy_runtime PROPERTIES TIMEOUT 40)
  add_test(NAME test_scanner_runtime COMMAND ${Python3_EXECUTABLE} -B
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_scanner_runtime.py $<TARGET_FILE:altprobe>)
  set_tests_properties(test_scanner_runtime PROPERTIES TIMEOUT 20)
endif()

install(TARGETS altprobe RUNTIME DESTINATION bin)

install(FILES
    etc/altprobe.yaml
    etc/api_guard.yaml
    etc/scoring_weights.yaml
    etc/sbom.yaml
    DESTINATION /etc/altprobe
)

install(PROGRAMS
    scripts/altprobe-start.sh
    scripts/altprobe-stop.sh
    scripts/altprobe-status.sh
    DESTINATION bin
)

set(ALTPROBE_CRS_VERSION "4.29.0" CACHE STRING "OWASP CRS version bundled into the .deb")
option(ALTPROBE_PACKAGE_CRS "Download and bundle OWASP CRS into the .deb" ON)
set(ALTPROBE_CRS_ARCHIVE "" CACHE FILEPATH "Local OWASP CRS archive for offline packaging")
set(ALTPROBE_CRS_ARCHIVE_SHA256 "" CACHE STRING "SHA-256 of the local OWASP CRS archive")

add_custom_target(package
    COMMAND ${CMAKE_COMMAND}
        -DALTPROBE_VERSION=${PROJECT_VERSION}
        -DALTPROBE_CRS_VERSION=${ALTPROBE_CRS_VERSION}
        -DALTPROBE_PACKAGE_CRS=${ALTPROBE_PACKAGE_CRS}
        -DALTPROBE_CRS_ARCHIVE=${ALTPROBE_CRS_ARCHIVE}
        -DALTPROBE_CRS_ARCHIVE_SHA256=${ALTPROBE_CRS_ARCHIVE_SHA256}
        -DALTPROBE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DALTPROBE_BINARY=$<TARGET_FILE:altprobe>
        -DALTPROBE_BUILD_DIR=${CMAKE_BINARY_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/PackageDeb.cmake
    DEPENDS altprobe
    COMMENT "Building altprobe .deb package (with OWASP CRS)"
    VERBATIM
)

