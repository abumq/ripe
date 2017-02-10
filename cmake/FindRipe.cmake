# Finds Ripe headers and OpenSSL as dependency
# Creates ${RIPE_INCLUDE_DIR}
set(RIPE_PATHS ${RIPE_ROOT} $ENV{RIPE_ROOT})

find_path(RIPE_INCLUDE_DIR
    Ripe.h
    RipeHelpers.h
    PATH_SUFFIXES include
    PATHS ${RIPE_PATHS}
)

find_library(RIPE_LIBRARY
    NAMES ripe libripe
    HINTS "${CMAKE_PREFIX_PATH}/lib"
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Ripe REQUIRED_VARS RIPE_INCLUDE_DIR)
