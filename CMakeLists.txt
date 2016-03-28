# Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

cmake_minimum_required (VERSION 2.8)

# Use the OpenSwitch definition to fit with the internal data structures
add_definitions(-DOPS)

set (IPSEC ops-ipsecd)
project (${IPSEC})
set (SRC_DIR src)
set (INCL_DIR include)

# Rules to locate needed libraries
include(FindPkgConfig)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)

pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)

# pthreads
find_package(Threads REQUIRED)
# Doxygen documentation
find_package(Doxygen)
# Boost Library
find_package(Boost)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

IF(DOXYGEN_FOUND)
    set(doxyfile ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)

    add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating documentation with Doxygen"
        VERBATIM)
ENDIF()

include_directories (${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/${INCL_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS}
)

# Define compile flags
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -ggdb -g3 -O0")

# Source files to build ops-ipsecd
set (SOURCES
        ${SRC_DIR}/ops_ipsecd.cpp
        ${SRC_DIR}/IKEViciAPI.cpp
        ${SRC_DIR}/ViciAPI.cpp
        ${SRC_DIR}/ops_ipsec_helper.cpp
        ${SRC_DIR}/ViciItem.cpp
        ${SRC_DIR}/ViciValue.cpp
        ${SRC_DIR}/ViciList.cpp
        ${SRC_DIR}/ViciSection.cpp
        ${SRC_DIR}/ViciStreamParser.cpp
        ${SRC_DIR}/UnixctlCommands.cpp
        ${SRC_DIR}/UnixctlCommandsUtils.cpp
        ${SRC_DIR}/DebugMode.cpp
        ${SRC_DIR}/SystemCalls.cpp
        ${SRC_DIR}/MapFile.cpp
        ${SRC_DIR}/StatPublisher.cpp
        ${SRC_DIR}/ConfigQueue.cpp
        ${SRC_DIR}/ConfigTask.cpp
        ${SRC_DIR}/ConfigTaskSA.cpp
        ${SRC_DIR}/ConfigTaskSP.cpp
        ${SRC_DIR}/ConfigTaskCA.cpp
        ${SRC_DIR}/ConfigTaskIKE.cpp
)

# Rules to build ops-ipsecd

find_library(VICI_LIBRARIES NAMES vici PATHS ${CMAKE_LIBRARY_PATH} PATH_SUFFIXES ipsec)
get_filename_component(VICI_LIB_PATH ${VICI_LIBRARIES} DIRECTORY)

SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath,/usr/lib/ipsec -L${VICI_LIB_PATH}")

add_executable (${IPSEC} ${SOURCES})

#Tests
add_subdirectory(tests)

IF (DOXYGEN_FOUND)
    add_dependencies(${IPSEC} doc)
ENDIF()

target_link_libraries (${IPSEC} ${OVSCOMMON_LIBRARIES} ${OVSDB_LIBRARIES} -lvici -lpthread -lrt)

# Rules to install ops-ipsecd binary in rootfs
install(TARGETS ${IPSEC}
        RUNTIME DESTINATION bin)
