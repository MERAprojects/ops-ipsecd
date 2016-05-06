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
include(ExternalProject)
include(FindPkgConfig)

pkg_check_modules(GTEST REQUIRED gtest>=1.7.0)
pkg_check_modules(GMOCK REQUIRED gmock>=1.7.0)

# pthreads
find_package(Threads REQUIRED)

# Google Test
enable_testing()
find_package(GTest REQUIRED)

set (IPSEC-UT ${IPSEC}-ut)
set (MAIN_SRC_DIR ../src)
set (MOCK_DIR mocks)

project(${IPSEC-UT} CXX)

# Add all tests files from current directory
execute_process(
         COMMAND find ${CMAKE_CURRENT_SOURCE_DIR} -type f -name *.cpp -printf "%P;"
         OUTPUT_VARIABLE TEST_SOURCES
)

set (MAIN_SOURCES
        ${MAIN_SRC_DIR}/IKEViciAPI.cpp
        ${MAIN_SRC_DIR}/ops_ipsec_helper.cpp
        ${MAIN_SRC_DIR}/ViciItem.cpp
        ${MAIN_SRC_DIR}/ViciValue.cpp
        ${MAIN_SRC_DIR}/ViciList.cpp
        ${MAIN_SRC_DIR}/ViciSection.cpp
        ${MAIN_SRC_DIR}/ViciStreamParser.cpp
        ${MAIN_SRC_DIR}/MapFile.cpp
        ${MAIN_SRC_DIR}/StatPublisher.cpp
        ${MAIN_SRC_DIR}/ConfigQueue.cpp
        ${MAIN_SRC_DIR}/ConfigTask.cpp
        ${MAIN_SRC_DIR}/ConfigTaskSA.cpp
        ${MAIN_SRC_DIR}/ConfigTaskSP.cpp
        ${MAIN_SRC_DIR}/ConfigTaskCA.cpp
        ${MAIN_SRC_DIR}/ConfigTaskIKE.cpp
        ${MAIN_SRC_DIR}/IPsecNetlinkAPI.cpp
        ${MAIN_SRC_DIR}/ErrorNotifySS.cpp
)

add_executable(${IPSEC-UT} ${TEST_SOURCES} ${MAIN_SOURCES})
include_directories(${GTEST_INCLUDE_DIRS} ${GMOCK_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/${MOCK_DIR})
target_link_libraries(${IPSEC-UT} ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
