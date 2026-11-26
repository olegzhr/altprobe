# Vendored pure library: validate this snapshot with scripts/check_shared.py.
add_library(probe_shared STATIC
    signal_names.cpp listener_transport.cpp identity.cpp api_guard.cpp request_classifier.cpp inventory_decode.cpp)
target_include_directories(probe_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(probe_shared PUBLIC BOOST_BIND_GLOBAL_PLACEHOLDERS)
target_link_libraries(probe_shared PUBLIC ${YAML_TARGET} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
