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

set (IPSEC ops-ipsecd)
project (${IPSEC})
set (SRC_DIR src)
set (INCL_DIR include)

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)

# pthreads
find_package(Threads REQUIRED)

include_directories (${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/${INCL_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS}
)

# Define compile flags
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -ggdb -g3 -O0")

# Source files to build ops-ipsecd
execute_process(
    COMMAND find ${CMAKE_CURRENT_SOURCE_DIR} -type f -name *.cpp -printf "%P;"
    OUTPUT_VARIABLE SOURCES
)


# Rules to build ops-ipsecd
add_executable (${IPSEC} ${SOURCES})

target_link_libraries (${IPSEC} ${OVSCOMMON_LIBRARIES} ${OVSDB_LIBRARIES} -lpthread -lrt)

# Rules to install ops-ipsecd binary in rootfs
install(TARGETS ${IPSEC}
        RUNTIME DESTINATION bin)

#Tests
add_subdirectory(tests)
