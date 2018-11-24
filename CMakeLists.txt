cmake_minimum_required(VERSION 2.8.12)

project(Ripe)

option(test "Build all tests" OFF)
option(travis "Build all tests for travis" OFF)
option(dll "DLL imports (Use on windows only)" OFF)
option(dll_export "DLL exports (Use on windows only)" OFF)
option (BUILD_SHARED_LIBS "build shared libraries" ON)

set (RIPE_VERSION "4.2.1")
set (RIPE_SOVERSION "4.2.1")

add_definitions (-DRIPE_VERSION="${RIPE_VERSION}")
add_definitions (-DELPP_NO_LOG_TO_FILE)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

include_directories (${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR})

include(FindPackageHandleStandardArgs)

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

list (APPEND CMAKE_CXX_FLAGS "  ")

if (dll)
    add_definitions (-DRIPE_DLL)
endif()

if (dll_export)
    add_definitions (-DRIPE_EXPORTS)
endif()

# Check for cryptopp (static)
set(CryptoPP_USE_STATIC_LIBS ON)
find_package(CryptoPP REQUIRED)
message ("-- Crypto++ binary: " ${CRYPTOPP_LIBRARY})
include_directories (${CRYPTOPP_INCLUDE_DIRS})

find_package(ZLIB REQUIRED)
if (ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
endif(ZLIB_FOUND)

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
)

if (BUILD_SHARED_LIBS)
    add_library(ripe SHARED ${LIB_RIPE_SOURCE_FILES})
else()
    add_library(ripe STATIC ${LIB_RIPE_SOURCE_FILES})
endif()

set_target_properties(ripe PROPERTIES
    VERSION ${RIPE_VERSION}
    SOVERSION ${RIPE_SOVERSION}
)

target_link_libraries(ripe
    ${CRYPTOPP_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

target_compile_definitions(ripe PRIVATE
    ELPP_NO_DEFAULT_LOG_FILE
    ELPP_DEFAULT_LOGGING_FLAGS=4096
)
install (TARGETS ripe DESTINATION lib)
install (FILES include/Ripe.h DESTINATION "include")

################################################ RIPE ##############################################

add_executable (ripe-bin src/ripe.cc lib/Ripe.cc)
#target_link_libraries (ripe-bin ripe)
target_link_libraries (ripe-bin ${CRYPTOPP_LIBRARIES} ${ZLIB_LIBRARIES})

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


# We need C++11 (only for test)
macro(require_cpp11)
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
                elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
                    message ("-- GNU CXX (-std=c++11)")
                    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
                else()
                    message ("-- Requires C++11. Your compiler does not support it.")
                endif()
        endif()
endmacro()

########################################## Unit Testing ###################################
if (test)

    require_cpp11()

    # Check for Easylogging++
    find_package(EASYLOGGINGPP REQUIRED)
    include_directories (${EASYLOGGINGPP_INCLUDE_DIR})

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
