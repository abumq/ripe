cmake_minimum_required(VERSION 2.8.12)

project(Ripe)

option(test "Build all tests" OFF)
option(travis "Build all tests for travis" OFF)

set (RIPE_VERSION "1.0")
set (RIPE_SOVERSION "1.0")

add_definitions (-DRIPE_VERSION="${RIPE_VERSION}")
add_definitions (-DELPP_NO_LOG_TO_FILE)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

include_directories (${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR})

option (BUILD_SHARED_LIBS "build shared libraries" OFF)
include(FindPackageHandleStandardArgs)

# We need C++11
if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.0)
        # CMake 3.1 has built-in CXX standard checks.
        message("-- Setting C++11")
        set(CMAKE_CXX_STANDARD 11)
        set(CMAKE_CXX_STANDARD_REQUIRED on)
else()
        if (CMAKE_CXX_COMPILER_ID MATCHES "GCC")
            message ("-- GNU CXX (-std=c++11)")
            list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
        elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            message ("-- CLang CXX (-std=c++11)")
            list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
        else()
            message ("-- Ripe requires C++11. Your compiler does not support it.")
        endif()
endif()

# http://www.cmake.org/Wiki/CMake_RPATH_handling#Mac_OS_X_and_the_RPATH
if (APPLE)
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
    if("${isSystemDir}" STREQUAL "-1")
        set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    endif()
endif()

if (travis)
else()
    list(APPEND CMAKE_CXX_FLAGS "-Wno-deprecated-declarations")
endif()

# Check for OpenSSL
find_package (openssl REQUIRED)
include_directories (${OPENSSL_INCLUDE_DIR})

# Check for Easylogging++
find_package(EASYLOGGINGPP REQUIRED)
include_directories (${EASYLOGGINGPP_INCLUDE_DIR})

# Check for include files and stdlib properties.
include (CheckIncludeFileCXX)
check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)

# Check if xattr functions take extra arguments, as they do on OSX.
# Output error is misleading, so do this test quietly.
include (CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_QUIET_SAVE ${CMAKE_REQUIRED_QUIET})
set (CMAKE_REQUIRED_QUIET True)
check_cxx_source_compiles ("#include <sys/types.h>
#include <sys/xattr.h>
int main() { getxattr(0,0,0,0,0,0); return 1; }
" XATTR_ADD_OPT)
set (CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_SAVE})

################################################ RIPE LIB #####################################

# Ripe lib
set(LIB_RIPE_SOURCE_FILES
    lib/Ripe.cc
    lib/RipeHelpers.cc
    ${EASYLOGGINGPP_INCLUDE_DIR}/easylogging++.cc
)

add_library(ripe SHARED ${LIB_RIPE_SOURCE_FILES})
set_target_properties(ripe PROPERTIES
    VERSION ${RIPE_VERSION}
    SOVERSION ${RIPE_SOVERSION}
)
target_link_libraries(ripe
    ${OPENSSL_LIBRARIES}
)

target_compile_definitions(ripe PRIVATE
    ELPP_NO_DEFAULT_LOG_FILE
    ELPP_DEFAULT_LOGGING_FLAGS=4096
)
install (TARGETS ripe DESTINATION lib)

################################################ RIPE ##############################################

add_executable (ripe-bin src/ripe.cc)
target_link_libraries (ripe-bin ripe)

set_target_properties (ripe-bin PROPERTIES
    OUTPUT_NAME "ripe"
    VERSION ${RIPE_VERSION}
    SOVERSION ${RIPE_SOVERSION}
)
install (TARGETS ripe-bin DESTINATION bin)

############################################################################################

# Reference all headers, to make certain IDEs happy.
file (GLOB_RECURSE all_headers ${CMAKE_SOURCE_DIR}/*.h)
add_custom_target (all_placeholder SOURCES ${all_headers})


########################################## Unit Testing ###################################
if (test)

    find_package (gtest REQUIRED)

    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

    enable_testing()

    add_executable(ripe-unit-tests
        test/main.cc
        ${EASYLOGGINGPP_INCLUDE_DIR}/easylogging++.cc
    )

    target_compile_definitions(ripe-unit-tests PUBLIC
        ELPP_FEATURE_ALL
        ELPP_DEFAULT_LOG_FILE="logs/ripe-unit-test.log"
        ELPP_DEFAULT_LOGGING_FLAGS=4096
    )

    # Standard linking to gtest stuff.
    target_link_libraries(ripe-unit-tests gtest gtest_main)

    # Extra linking for the project.
    target_link_libraries(ripe-unit-tests ripe) 

    add_test(NAME ripeUnitTests COMMAND ripe-unit-tests)
endif()
