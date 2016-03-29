/*
 *  (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain
 *  a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */

/**********************************
*System Includes
**********************************/
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gtest/gtest.h>

/**********************************
*Local Includes
**********************************/
#include "MapFile.h"
#include "ops-ipsecd.h"
#include "mocks/mock_ISystemCalls.h"

/**********************************
*Using
**********************************/
using ::testing::_;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Test;
using ::testing::StrEq;
using ::testing::IsNull;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::SetArgPointee;

class FakeCalls
{
    public:

        struct stat m_stat;

        int s_fstat(int fd, struct stat *buf)
        {
            buf->st_size = m_stat.st_size;

            return 0;
        }
};

class MapFile_EnO : public MapFile
{
    public:

        MapFile_EnO(ISystemCalls& systemCalls)
            : MapFile(systemCalls)
        {
        }

        void set_size(uint32_t value)
        {
            m_size = value;
        }

        void set_map_file(void* value)
        {
            m_map_file = value;
        }

        void call_unmap_file()
        {
            unmap_file();
        }
};

class MapFileTestSuite : public Test
{
    public:

        MockISystemCalls m_SystemCalls;
        MapFile_EnO m_MapFile;

        MapFileTestSuite()
            : m_MapFile(m_SystemCalls)
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
            m_MapFile.set_size(0);
            m_MapFile.set_map_file(nullptr);
        }
};

/**
 * Objective: Verify that Map File can map a file
 **/
TEST_F(MapFileTestSuite, TestMapFile)
{
    FakeCalls fakeCalls;

    int fd = 222;
    void* file_map = (void*)0x100;
    fakeCalls.m_stat.st_size = 333;
    std::string filepath = "TestFile.txt";

    EXPECT_EQ(m_MapFile.get_map_file(), nullptr);
    EXPECT_EQ(m_MapFile.get_size(), 0);

    ON_CALL(m_SystemCalls, s_fstat(_, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::s_fstat));

    EXPECT_CALL(m_SystemCalls, s_open(StrEq(filepath), O_RDONLY))
            .WillOnce(Return(fd));

    EXPECT_CALL(m_SystemCalls, s_fstat(Eq(fd), NotNull()));

    EXPECT_CALL(m_SystemCalls, s_mmap(IsNull(), Eq(fakeCalls.m_stat.st_size),
                        Eq(PROT_READ), Eq(MAP_PRIVATE), Eq(fd), Eq(0)))
            .WillOnce(Return(file_map));

    EXPECT_EQ(m_MapFile.map_file(filepath), ipsec_ret::OK);
    EXPECT_EQ(m_MapFile.get_map_file(), file_map);
    EXPECT_EQ(m_MapFile.get_size(), fakeCalls.m_stat.st_size);
}

/**
 * Objective: Verify that Map File can map a file and unmap a previous map file
 **/
TEST_F(MapFileTestSuite, TestMapFileFileMapped)
{
    FakeCalls fakeCalls;

    void* file_map_prev = (void*)0x100;
    uint32_t size_prev = 111;

    m_MapFile.set_map_file(file_map_prev);
    m_MapFile.set_size(size_prev);

    EXPECT_CALL(m_SystemCalls, s_munmap(Eq(file_map_prev), Eq(size_prev)))
            .WillOnce(Return(0));

    int fd = 222;
    void* file_map = (void*)0x100;
    fakeCalls.m_stat.st_size = 333;
    std::string filepath = "TestFile.txt";

    ON_CALL(m_SystemCalls, s_fstat(_, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::s_fstat));

    EXPECT_CALL(m_SystemCalls, s_open(StrEq(filepath), O_RDONLY))
            .WillOnce(Return(fd));

    EXPECT_CALL(m_SystemCalls, s_fstat(Eq(fd), NotNull()));

    EXPECT_CALL(m_SystemCalls, s_mmap(IsNull(), Eq(fakeCalls.m_stat.st_size),
                        Eq(PROT_READ), Eq(MAP_PRIVATE), Eq(fd), Eq(0)))
            .WillOnce(Return(file_map));

    EXPECT_EQ(m_MapFile.map_file(filepath), ipsec_ret::OK);
    EXPECT_EQ(m_MapFile.get_map_file(), file_map);
    EXPECT_EQ(m_MapFile.get_size(), fakeCalls.m_stat.st_size);
}

/**
 * Objective: Verify that Map File will return the correct error
 * if the file cannot be open
 **/
TEST_F(MapFileTestSuite, TestMapFileOpenFileFailed)
{
    std::string filepath = "TestFile.txt";

    EXPECT_CALL(m_SystemCalls, s_open(StrEq(filepath), O_RDONLY))
            .WillOnce(Return(-1));

    EXPECT_EQ(m_MapFile.map_file(filepath), ipsec_ret::OPEN_FAILED);
    EXPECT_EQ(m_MapFile.get_map_file(), nullptr);
    EXPECT_EQ(m_MapFile.get_size(), 0);
}

/**
 * Objective: Verify that Map File will return the correct error
 * if fstat does not work
 **/
TEST_F(MapFileTestSuite, TestMapFileFstatFailed)
{
    int fd = 222;
    std::string filepath = "TestFile.txt";

    EXPECT_CALL(m_SystemCalls, s_open(StrEq(filepath), O_RDONLY))
            .WillOnce(Return(fd));

    EXPECT_CALL(m_SystemCalls, s_fstat(Eq(fd), NotNull()))
            .WillOnce(Return(-1));

    EXPECT_EQ(m_MapFile.map_file(filepath), ipsec_ret::SSTAT_FAILED);
    EXPECT_EQ(m_MapFile.get_map_file(), nullptr);
    EXPECT_EQ(m_MapFile.get_size(), 0);
}

/**
 * Objective: Verify that Map File will return the correct error
 * if mmap does not work
 **/
TEST_F(MapFileTestSuite, TestMapFileMMAPFailed)
{
    FakeCalls fakeCalls;

    int fd = 222;
    fakeCalls.m_stat.st_size = 333;
    std::string filepath = "TestFile.txt";

    EXPECT_EQ(m_MapFile.get_map_file(), nullptr);
    EXPECT_EQ(m_MapFile.get_size(), 0);

    ON_CALL(m_SystemCalls, s_fstat(_, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::s_fstat));

    EXPECT_CALL(m_SystemCalls, s_open(StrEq(filepath), O_RDONLY))
            .WillOnce(Return(fd));

    EXPECT_CALL(m_SystemCalls, s_fstat(Eq(fd), NotNull()));

    EXPECT_CALL(m_SystemCalls, s_mmap(IsNull(), Eq(fakeCalls.m_stat.st_size),
                        Eq(PROT_READ), Eq(MAP_PRIVATE), Eq(fd), Eq(0)))
            .WillOnce(Return(MAP_FAILED));

    EXPECT_EQ(m_MapFile.map_file(filepath), ipsec_ret::MMAP_FAILED);
    EXPECT_EQ(m_MapFile.get_map_file(), nullptr);
    EXPECT_EQ(m_MapFile.get_size(), fakeCalls.m_stat.st_size);
}

/**
 * Objective: Verify that Map File can unmap the file
 **/
TEST_F(MapFileTestSuite, TestUnmap)
{
    void* file_map = (void*)0x100;
    uint32_t size = 111;

    m_MapFile.set_map_file(file_map);
    m_MapFile.set_size(size);

    EXPECT_CALL(m_SystemCalls, s_munmap(Eq(file_map), Eq(size)))
            .WillOnce(Return(0));

    m_MapFile.call_unmap_file();
    EXPECT_EQ(m_MapFile.get_map_file(), nullptr);
    EXPECT_EQ(m_MapFile.get_size(), 0);
}

/**
 * Objective: Verify that Map File method get size works
 **/
TEST_F(MapFileTestSuite, TestGetSize)
{
    uint32_t size = 111;

    m_MapFile.set_size(size);

    EXPECT_EQ(m_MapFile.get_size(), size);
}

/**
 * Objective: Verify that Map File method get map file works
 **/
TEST_F(MapFileTestSuite, TestGetMapFile)
{
    void* file_map = (void*)0x100;

    m_MapFile.set_map_file(file_map);

    EXPECT_EQ(m_MapFile.get_map_file(), file_map);
}
