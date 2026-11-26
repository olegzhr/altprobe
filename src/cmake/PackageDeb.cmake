if(NOT ALTPROBE_VERSION)
    message(FATAL_ERROR "ALTPROBE_VERSION is required")
endif()

set(CRS_VERSION "${ALTPROBE_CRS_VERSION}")
set(STAGE "${ALTPROBE_BUILD_DIR}/package/altprobe_${ALTPROBE_VERSION}_amd64")
set(DEB_FILE "${ALTPROBE_BUILD_DIR}/altprobe_${ALTPROBE_VERSION}_amd64.deb")
set(CRS_ARCHIVE "${ALTPROBE_BUILD_DIR}/package/crs-${CRS_VERSION}.tar.gz")
set(CRS_EXTRACTED "${ALTPROBE_BUILD_DIR}/package/coreruleset-${CRS_VERSION}")

file(REMOVE_RECURSE "${ALTPROBE_BUILD_DIR}/package")
file(MAKE_DIRECTORY
    "${STAGE}/DEBIAN"
    "${STAGE}/usr/local/bin"
    "${STAGE}/etc/altprobe"
    "${STAGE}/etc/altprobe/coreruleset"
)

file(COPY "${ALTPROBE_BINARY}" DESTINATION "${STAGE}/usr/local/bin")
file(COPY
    "${ALTPROBE_SOURCE_DIR}/scripts/altprobe-start.sh"
    "${ALTPROBE_SOURCE_DIR}/scripts/altprobe-stop.sh"
    "${ALTPROBE_SOURCE_DIR}/scripts/altprobe-status.sh"
    DESTINATION "${STAGE}/usr/local/bin"
)
foreach(name IN ITEMS start stop status)
    file(RENAME
        "${STAGE}/usr/local/bin/altprobe-${name}.sh"
        "${STAGE}/usr/local/bin/altprobe-${name}"
    )
endforeach()
file(COPY
    "${ALTPROBE_SOURCE_DIR}/etc/altprobe.yaml"
    "${ALTPROBE_SOURCE_DIR}/etc/api_guard.yaml"
    "${ALTPROBE_SOURCE_DIR}/etc/scoring_weights.yaml"
    "${ALTPROBE_SOURCE_DIR}/etc/sbom.yaml"
    DESTINATION "${STAGE}/etc/altprobe"
)

execute_process(COMMAND chmod 0644
    "${STAGE}/etc/altprobe/altprobe.yaml"
    "${STAGE}/etc/altprobe/api_guard.yaml"
    "${STAGE}/etc/altprobe/scoring_weights.yaml"
    "${STAGE}/etc/altprobe/sbom.yaml"
)

if(ALTPROBE_PACKAGE_CRS)
    if(ALTPROBE_CRS_ARCHIVE)
        if(NOT EXISTS "${ALTPROBE_CRS_ARCHIVE}" OR NOT ALTPROBE_CRS_ARCHIVE_SHA256)
            message(FATAL_ERROR "A cached CRS archive requires an existing file and ALTPROBE_CRS_ARCHIVE_SHA256")
        endif()
        file(SHA256 "${ALTPROBE_CRS_ARCHIVE}" cached_crs_sha256)
        if(NOT cached_crs_sha256 STREQUAL ALTPROBE_CRS_ARCHIVE_SHA256)
            message(FATAL_ERROR "Cached CRS archive SHA256 mismatch")
        endif()
        message(STATUS "Using SHA256-verified OWASP CRS ${CRS_VERSION} archive")
        configure_file("${ALTPROBE_CRS_ARCHIVE}" "${CRS_ARCHIVE}" COPYONLY)
    else()
        message(STATUS "Downloading OWASP CRS ${CRS_VERSION}")
        execute_process(
            COMMAND curl -L --fail --silent --show-error --connect-timeout 10 --max-time 90 --retry 2 --retry-max-time 120
                "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
                -o "${CRS_ARCHIVE}"
            RESULT_VARIABLE curl_result
        )
        if(NOT curl_result EQUAL 0)
            message(FATAL_ERROR "Failed to download OWASP CRS ${CRS_VERSION}")
        endif()
    endif()

    execute_process(
        COMMAND tar -xzf "${CRS_ARCHIVE}" -C "${ALTPROBE_BUILD_DIR}/package"
        RESULT_VARIABLE tar_result
    )
    if(NOT tar_result EQUAL 0)
        message(FATAL_ERROR "Failed to extract OWASP CRS ${CRS_VERSION}")
    endif()

    file(COPY "${CRS_EXTRACTED}/" DESTINATION "${STAGE}/etc/altprobe/coreruleset")
    execute_process(COMMAND find "${STAGE}/etc/altprobe/coreruleset" -type f -exec chmod 0644 {} +)
    file(REMOVE_RECURSE "${CRS_EXTRACTED}" "${CRS_ARCHIVE}")
endif()

find_program(DPKG_SHLIBDEPS_EXECUTABLE NAMES dpkg-shlibdeps)
if(NOT DPKG_SHLIBDEPS_EXECUTABLE)
    message(FATAL_ERROR "dpkg-shlibdeps is required to build the package (install dpkg-dev)")
endif()

set(SHLIBDEPS_DIR "${ALTPROBE_BUILD_DIR}/package/shlibdeps")
file(MAKE_DIRECTORY "${SHLIBDEPS_DIR}/debian")
file(WRITE "${SHLIBDEPS_DIR}/debian/control"
"Source: altprobe
Section: base
Priority: optional
Maintainer: Oleg Zharkov <olegzhr@users.noreply.github.com>
Standards-Version: 4.5.0

Package: altprobe
Architecture: any
Description: Altprobe
 Altprobe event collector and native test drivers.
")

execute_process(
    COMMAND "${DPKG_SHLIBDEPS_EXECUTABLE}" -O "${STAGE}/usr/local/bin/altprobe"
    WORKING_DIRECTORY "${SHLIBDEPS_DIR}"
    OUTPUT_VARIABLE shlibdeps_output
    ERROR_VARIABLE shlibdeps_error
    RESULT_VARIABLE shlibdeps_result
)
if(NOT shlibdeps_result EQUAL 0)
    message(FATAL_ERROR "dpkg-shlibdeps failed: ${shlibdeps_error}")
endif()
if(NOT shlibdeps_output MATCHES "shlibs:Depends=([^\n]+)")
    message(FATAL_ERROR "dpkg-shlibdeps produced no dependency list: ${shlibdeps_output}")
endif()
string(STRIP "${CMAKE_MATCH_1}" RUNTIME_DEPENDS)

file(WRITE "${STAGE}/DEBIAN/control"
"Package: altprobe
Version: ${ALTPROBE_VERSION}
Section: base
Priority: optional
Architecture: amd64
Maintainer: Oleg Zharkov <olegzhr@users.noreply.github.com>
Depends: ${RUNTIME_DEPENDS}
Description: Altprobe
 Altprobe event collector and native test drivers.
")

file(WRITE "${STAGE}/DEBIAN/postinst"
"#!/bin/sh
set -e
chmod o-rwx /etc/altprobe/altprobe.yaml || true
exit 0
")

execute_process(COMMAND chmod 0755
    "${STAGE}/usr/local/bin/altprobe"
    "${STAGE}/usr/local/bin/altprobe-start"
    "${STAGE}/usr/local/bin/altprobe-stop"
    "${STAGE}/usr/local/bin/altprobe-status"
    "${STAGE}/DEBIAN/postinst"
    RESULT_VARIABLE chmod_result
)
if(NOT chmod_result EQUAL 0)
    message(FATAL_ERROR "Failed to set package file permissions")
endif()

# dpkg must preserve locally edited endpoints, credentials, rules and scanner
# commands on upgrade/reinstall, including packages republished as 1.0.2.
set(CONFFILES "")
foreach(name IN ITEMS altprobe.yaml api_guard.yaml scoring_weights.yaml sbom.yaml)
    string(APPEND CONFFILES "/etc/altprobe/${name}\n")
endforeach()
file(GLOB_RECURSE CRS_CONFIGS RELATIVE "${STAGE}"
    "${STAGE}/etc/altprobe/coreruleset/*.conf"
    "${STAGE}/etc/altprobe/coreruleset/*.conf.example")
list(SORT CRS_CONFIGS)
foreach(name IN LISTS CRS_CONFIGS)
    string(APPEND CONFFILES "/${name}\n")
endforeach()
file(WRITE "${STAGE}/DEBIAN/conffiles" "${CONFFILES}")

execute_process(COMMAND dpkg-deb --build --root-owner-group "${STAGE}" "${DEB_FILE}"
    RESULT_VARIABLE deb_result
)
if(NOT deb_result EQUAL 0)
    message(FATAL_ERROR "dpkg-deb failed")
endif()

message(STATUS "Created ${DEB_FILE}")
