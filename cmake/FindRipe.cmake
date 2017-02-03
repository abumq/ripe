set(RIPE_PATHS ${RIPE_ROOT} $ENV{RIPE_ROOT})

find_path(RIPE_INCLUDE_DIR
        Ripe.h
        PATH_SUFFIXES include
        PATHS ${Ripe_PATHS}
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Ripe REQUIRED_VARS Ripe_INCLUDE_DIR)
