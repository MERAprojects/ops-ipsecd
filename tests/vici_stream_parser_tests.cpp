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
#include <gtest/gtest.h>

/**********************************
*Local Includes
**********************************/
#include "ViciList.h"
#include "ViciValue.h"
#include "ops-ipsecd.h"
#include "ViciSection.h"
#include "ViciStreamParser.h"
#include "mocks/mock_IViciAPI.h"

/**********************************
*Using
**********************************/
using ::testing::_;
using ::testing::Eq;
using ::testing::Test;
using ::testing::StrEq;
using ::testing::Invoke;
using ::testing::IsNull;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::InSequence;

class FakeCalls
{
    public:

        ViciStreamParser::DataCB m_data_cb;

        int parse_cb_data_cb(vici_res_t *res, vici_parse_section_cb_t section,
                             vici_parse_value_cb_t kv, vici_parse_value_cb_t li,
                             void *user)
        {
            ViciStreamParser::DataCB* paramData =
                    (ViciStreamParser::DataCB*)user;

            EXPECT_NE(paramData, nullptr);
            if(paramData == nullptr)
            {
                return -1;
            }

            EXPECT_EQ(m_data_cb.m_section, paramData->m_section);
            EXPECT_EQ(m_data_cb.m_vici_api, paramData->m_vici_api);

            return 0;
        }
};

class ViciSection_EnO : public ViciSection
{
    public:

        ViciItemMap& get_map()
        {
            return m_items;
        }
};

class ViciStreamParser_EnO : public ViciStreamParser
{
    public:

        ViciStreamParser_EnO(IViciAPI& vici_api)
            : ViciStreamParser(vici_api)
        {
        }

        void set_parse_status(ipsec_ret value)
        {
            m_parse_status = value;
        }

        ViciSection& get_vici_section()
        {
            return m_vici_section;
        }

        const std::string& get_event_registered()
        {
            return m_event_registered;
        }

        vici_conn_t* get_conn_registered()
        {
            return m_conn_registered;
        }

        void set_event_registered(const std::string& value)
        {
            m_event_registered = value;
        }

        void set_conn_registered(vici_conn_t* value)
        {
            m_conn_registered = value;
        }

        int call_parse_section(void* user, vici_res_t* res, char* name)
        {
            return parse_section(user, res, name);
        }

        int call_parse_key_value(void* user, vici_res_t* res, char* name,
                                   void* value, int len)
        {
            return parse_key_value(user, res, name, value, len);
        }

        int call_parse_list_item(void* user, vici_res_t* res, char* name,
                                   void* value, int len)
        {
            return parse_list_item(user, res, name, value, len);
        }

        void call_event_cb(void* user, char* name, vici_res_t* res)
        {
            return event_cb(user, name, res);
        }

        static vici_parse_section_cb_t get_parse_section_addr()
        {
            return parse_section;
        }

        static vici_parse_value_cb_t get_parse_key_value_addr()
        {
            return parse_key_value;
        }

        static vici_parse_value_cb_t get_parse_list_item_addr()
        {
            return parse_list_item;
        }

        static vici_event_cb_t get_event_cb_addr()
        {
            return event_cb;
        }

};

class ViciStreamParserTestSuite : public Test
{
    public:

        MockIViciAPI m_vici_api;

        ViciStreamParserTestSuite()
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
        }
};

/**
 * Objective: Verify that the Vici Value Type is set correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciValueType)
{
    ViciValue value;

    EXPECT_EQ(value.get_vici_item_type(), ViciItemType::Value);
}

/**
 * Objective: Verify that the Vici Storage Value
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSetGetValue)
{
    ViciValue viciValue;
    std::string testValue = "Test_Vici_Value";

    viciValue.set_value(testValue);

    EXPECT_EQ(viciValue.get_value().compare(testValue), 0);
}

/**
 * Objective: Verify that the Vici List Type is set correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciListType)
{
    ViciList viciList;

    EXPECT_EQ(viciList.get_vici_item_type(), ViciItemType::List);
}

/**
 * Objective: Verify that Adding an Element to the List works correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciAddElement)
{
    ViciList viciList;
    std::string testElement = "Test_List";

    viciList.add_value(testElement);

    EXPECT_EQ(viciList.get_value(0).compare(testElement), 0);
}

/**
 * Objective: Verify that the size of the list is return correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciGetSize)
{
    ViciList viciList;

    EXPECT_EQ(viciList.get_size(), 0);

    viciList.add_value("1");
    viciList.add_value("2");
    viciList.add_value("3");
    viciList.add_value("4");
    viciList.add_value("5");

    EXPECT_EQ(viciList.get_size(), 5);
}

/**
 * Objective: Verify that Adding an Element is added in the correct order
 **/
TEST_F(ViciStreamParserTestSuite, TestViciListAddElementOrdered)
{
    ViciList viciList;

    EXPECT_EQ(viciList.get_size(), 0);

    viciList.add_value("1");
    viciList.add_value("2");
    viciList.add_value("3");

    EXPECT_EQ(viciList.get_value(0).compare("1"), 0);
    EXPECT_EQ(viciList.get_value(1).compare("2"), 0);
    EXPECT_EQ(viciList.get_value(2).compare("3"), 0);
}

/**
 * Objective: Verify that Getting an invalid element will
 * return an empty string
 **/
TEST_F(ViciStreamParserTestSuite, TestViciListGetInvalidElement)
{
    ViciList viciList;

    EXPECT_EQ(viciList.get_size(), 0);

    viciList.add_value("1");

    EXPECT_EQ(viciList.get_value(0).compare("1"), 0);
    EXPECT_EQ(viciList.get_value(1).compare(""), 0);
}

/**
 * Objective: Verify that the Vici Section Type is set correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionType)
{
    ViciSection viciSection;

    EXPECT_EQ(viciSection.get_vici_item_type(), ViciItemType::Section);
}

/**
 * Objective: Verify that the Vici Section Name can be set correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionSetGetName)
{
    ViciSection viciSection;
    std::string sectionName = "Test_Section";

    viciSection.set_name(sectionName);

    EXPECT_EQ(viciSection.get_name().compare(sectionName), 0);
}

/**
 * Objective: Verify Vici Section Clear Function
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionClear)
{
    ViciSection_EnO viciSection;
    ViciItemMap& viciSectionMap = viciSection.get_map();

    EXPECT_EQ(viciSectionMap.size(), 0);

    ViciValue* viciValue1 = new ViciValue();
    ViciValue* viciValue2 = new ViciValue();
    ViciValue* viciValue3 = new ViciValue();

    viciSection.set_item("1", viciValue1);
    viciSection.set_item("2", viciValue2);
    viciSection.set_item("3", viciValue3);

    EXPECT_EQ(viciSectionMap.size(), 3);

    viciSection.clear();

    EXPECT_EQ(viciSectionMap.size(), 0);
}

/**
 * Objective: Verify Vici Section Get Size
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionSize)
{
    ViciSection viciSection;

    ViciValue* viciValue1 = new ViciValue();
    ViciValue* viciValue2 = new ViciValue();
    ViciValue* viciValue3 = new ViciValue();

    viciSection.set_item("1", viciValue1);
    EXPECT_EQ(viciSection.get_size(), 1);
    viciSection.set_item("2", viciValue2);
    EXPECT_EQ(viciSection.get_size(), 2);
    viciSection.set_item("3", viciValue3);
    EXPECT_EQ(viciSection.get_size(), 3);
}

/**
 * Objective: Verify that the Vici Section item can be added
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionAddItem)
{
    ViciSection viciSection;
    std::string itemName = "Test_Name_Value";

    std::string valueTest = "Test_Value";
    ViciValue* viciValue = new ViciValue();
    viciValue->set_value(valueTest);

    viciSection.set_item(itemName, viciValue);

    const ViciItem* retItem = viciSection.get_item(itemName);

    ASSERT_NE(retItem, nullptr);
    ASSERT_EQ(retItem, viciValue);
    ASSERT_EQ(retItem->get_vici_item_type(), ViciItemType::Value);

    const ViciValue* retValueItem = dynamic_cast<const ViciValue*>(retItem);
    ASSERT_NE(retItem, nullptr);

    EXPECT_EQ(retValueItem->get_value().compare(valueTest), 0);
}

/**
 * Objective: Verify that the Vici Section Get Item Type will return correctly
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionGetItemType)
{
    ViciSection viciSection;

    std::string itemNameValue = "Test_Name_Value";
    std::string valueTestValue = "Test_Value";

    std::string itemNameList = "Test_Name_List";
    std::string valueTestList = "Test_List";

    ViciValue* viciValue = new ViciValue();
    viciValue->set_value(valueTestValue);
    viciSection.set_item(itemNameValue, viciValue);

    ViciList* viciList = new ViciList();
    viciList->add_value(valueTestList);
    viciSection.set_item(itemNameList, viciList);

    /////////////////////////////////////////////////////////
    ViciValue* retValue = viciSection.get_item_type<ViciValue>(itemNameValue);
    ASSERT_NE(retValue, nullptr);
    ASSERT_EQ(retValue->get_vici_item_type(), ViciItemType::Value);
    EXPECT_EQ(retValue->get_value().compare(valueTestValue), 0);

    ViciList* retList = viciSection.get_item_type<ViciList>(itemNameList);
    ASSERT_NE(retList, nullptr);
    ASSERT_EQ(retList->get_vici_item_type(), ViciItemType::List);
    EXPECT_EQ(retList->get_value(0).compare(valueTestList), 0);
}

/**
 * Objective: Verify that the Vici Section Get Item Type will return null if
 * a non-child class of Vici Item is set as the type
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionGetItemTypeWrongType)
{
    ViciSection viciSection;

    std::string itemNameValue = "Test_Name_Value";
    std::string valueTestValue = "Test_Value";

    ViciValue* viciValue = new ViciValue();
    viciValue->set_value(valueTestValue);
    viciSection.set_item(itemNameValue, viciValue);

    /////////////////////////////////////////////////////////
    ViciStreamParser* retValue =
            viciSection.get_item_type<ViciStreamParser>(itemNameValue);
    EXPECT_EQ(retValue, nullptr);
}

/**
 * Objective: Verify Vici Section Iterators
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionIterators)
{
    ViciSection_EnO viciSection;
    ViciValue* viciValue1 = new ViciValue();
    ViciValue* viciValue2 = new ViciValue();
    ViciValue* viciValue3 = new ViciValue();

    viciSection.set_item("1", viciValue1);
    viciSection.set_item("2", viciValue2);
    viciSection.set_item("3", viciValue3);

    ViciItemMap& viciSectionMap = viciSection.get_map();
    const ViciItemMap& viciSectionMapConst = viciSection.get_map();

    EXPECT_EQ(viciSection.begin(), viciSectionMap.begin());
    EXPECT_EQ(viciSection.end(), viciSectionMap.end());

    EXPECT_EQ(((const ViciSection_EnO*)&viciSection)->begin(),
              viciSectionMapConst.begin());
    EXPECT_EQ(((const ViciSection_EnO*)&viciSection)->end(),
              viciSectionMapConst.end());

    EXPECT_EQ(viciSection.cbegin(), viciSectionMap.cbegin());
    EXPECT_EQ(viciSection.cend(), viciSectionMap.cend());
}

/**
 * Objective: Verify that the Vici Section item can be removed
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionRemoveItem)
{
    ViciSection viciSection;
    std::string itemName = "Test_Name_Value";

    EXPECT_EQ(viciSection.get_size(), 0);

    std::string valueTest = "Test_Value";
    ViciValue* viciValue = new ViciValue();
    viciValue->set_value(valueTest);
    viciSection.set_item(itemName, viciValue);

    EXPECT_EQ(viciSection.get_size(), 1);

    EXPECT_TRUE(viciSection.remove_item(itemName));

    EXPECT_EQ(viciSection.get_size(), 0);
    EXPECT_EQ(viciSection.get_item(itemName), nullptr);
}

/**
 * Objective: Verify that the Vici Section item will not be remove if given the
 * wrong name
 **/
TEST_F(ViciStreamParserTestSuite, TestViciSectionRemoveItemNotFound)
{
    ViciSection viciSection;
    std::string itemName = "Test_Name_Value";
    std::string itemNameWrong = "Test_Name_Value_Wrong";

    EXPECT_EQ(viciSection.get_size(), 0);

    std::string valueTest = "Test_Value";
    ViciValue* viciValue = new ViciValue();
    viciValue->set_value(valueTest);
    viciSection.set_item(itemName, viciValue);

    EXPECT_EQ(viciSection.get_size(), 1);

    EXPECT_FALSE(viciSection.remove_item(itemNameWrong));

    EXPECT_EQ(viciSection.get_size(), 1);
    EXPECT_NE(viciSection.get_item(itemName), nullptr);
}

/**
 * Objective: Verify that the Vici Stream Parser, Parse Status will be correctly
 * returned.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserGetParseStatus)
{
    ViciStreamParser_EnO parser(m_vici_api);

    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::NOT_PARSE);

    parser.set_parse_status(ipsec_ret::OK);

    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::OK);
}

/**
 * Objective: Verify that the Vici Section answer will be correctly
 * returned.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserGetViciAnswer)
{
    ViciStreamParser_EnO parser(m_vici_api);

    std::string viciStrValue = "Test_VICI_VALUE";
    std::string viciKeyValue = "Test_VICI_KEY";

    ViciValue* viciValue = new ViciValue();
    viciValue->set_value(viciStrValue);

    ViciSection& section = parser.get_vici_section();
    section.set_item(viciKeyValue, viciValue);

    //////////////////////////////////////////////////

    const ViciSection& retSection = parser.get_vici_section();

    ViciValue* retValue =
            reinterpret_cast<ViciValue*>(retSection.get_item(viciKeyValue));

    ASSERT_NE(retValue, nullptr);

    EXPECT_EQ(retValue->get_value().compare(viciStrValue), 0);
}

/**
 * Objective: Verify that the Parser can unregister an event correctly.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserUnregisterEvent)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_conn_t* testConn = (vici_conn_t*)0x100;
    std::string eventTest = "Test_Test";

    parser.set_event_registered(eventTest);
    parser.set_conn_registered(testConn);

    EXPECT_CALL(m_vici_api, register_cb(Eq(testConn), StrEq(eventTest),
                                        IsNull(), IsNull()))
            .WillOnce(Return(0));


    //////////////////////////////////////////////////

    parser.unregister_stream_cb();

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());
}

/**
 * Objective: Verify that the Parser if not event is register than no action
 * will be taken when unregister is called.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserUnregisterEventNotRegister)
{
    ViciStreamParser_EnO parser(m_vici_api);

    parser.set_event_registered("");
    parser.set_conn_registered(nullptr);

    //////////////////////////////////////////////////

    parser.unregister_stream_cb();

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());
}

/**
 * Objective: Verify that the Parser will return a correct error if register
 * is called with a null connection
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserRegisterEventConnNull)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_conn_t* testConn = nullptr;
    std::string eventTest = "Test_Test";

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());

    EXPECT_EQ(parser.register_stream_cb(testConn, eventTest),
              ipsec_ret::NULL_PARAMETERS);

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());
}

/**
 * Objective: Verify that the Parser will return a correct error if register
 * is called with a empty event name
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserRegisterEventEventEmpty)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_conn_t* testConn = (vici_conn_t*)0x100;
    std::string eventTest = "";

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());

    EXPECT_EQ(parser.register_stream_cb(testConn, eventTest),
              ipsec_ret::EMPTY_STRING);

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());
}

/**
 * Objective: Verify that the Parser can register an event correctly.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserRegisterEvent)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_conn_t* testConn = (vici_conn_t*)0x100;
    std::string eventTest = "Test_Test";

    ViciSection& section = parser.get_vici_section();
    ViciValue* testValue = new ViciValue();
    section.set_item("Test", testValue);
    testValue = nullptr;

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());

    EXPECT_CALL(m_vici_api, register_cb(Eq(testConn),
                                StrEq(eventTest),
                                Eq(ViciStreamParser_EnO::get_event_cb_addr()),
                                Eq((&parser))))
            .WillOnce(Return(0));

    EXPECT_EQ(parser.register_stream_cb(testConn, eventTest), ipsec_ret::OK);

    EXPECT_EQ(parser.get_conn_registered(), testConn);
    EXPECT_EQ(parser.get_event_registered().compare(eventTest), 0);
    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::NOT_PARSE);
    EXPECT_EQ(parser.get_vici_answer().get_size(), 0);

    parser.set_conn_registered(nullptr);
}

/**
 * Objective: Verify that the Parser can will return the correct error if an
 * event cannot be registered
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserRegisterEventFailed)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_conn_t* testConn = (vici_conn_t*)0x100;
    std::string eventTest = "Test_Test";

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());

    EXPECT_CALL(m_vici_api, register_cb(
                                Eq(testConn),
                                StrEq(eventTest),
                                Eq(ViciStreamParser_EnO::get_event_cb_addr()),
                                Eq((&parser))))
            .WillOnce(Return(-1));

    EXPECT_EQ(parser.register_stream_cb(testConn, eventTest),
              ipsec_ret::REGISTER_FAILED);

    EXPECT_EQ(parser.get_conn_registered(), nullptr);
    EXPECT_TRUE(parser.get_event_registered().empty());
    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::NOT_PARSE);
}

/**
 * Objective: Verify that the Parser can register an event correctly even if one
 * is already registered.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserRegisterEventWithEventOn)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_conn_t* testConn = (vici_conn_t*)0x100;
    std::string eventTest = "Test_Test";
    std::string eventTestPre = "Test_PreTest";

    ViciSection& section = parser.get_vici_section();
    ViciValue* testValue = new ViciValue();
    section.set_item("Test", testValue);
    testValue = nullptr;

    parser.set_conn_registered(testConn);
    parser.set_event_registered(eventTestPre);

    {
        InSequence s;

        EXPECT_CALL(m_vici_api, register_cb(Eq(testConn), StrEq(eventTestPre),
                                            IsNull(), IsNull()))
                .WillOnce(Return(0));

        EXPECT_CALL(m_vici_api, register_cb(Eq(testConn),
                                StrEq(eventTest),
                                Eq(ViciStreamParser_EnO::get_event_cb_addr()),
                                Eq((&parser))))
                .WillOnce(Return(0));
    }

    EXPECT_EQ(parser.register_stream_cb(testConn, eventTest), ipsec_ret::OK);

    EXPECT_EQ(parser.get_conn_registered(), testConn);
    EXPECT_EQ(parser.get_event_registered().compare(eventTest), 0);
    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::NOT_PARSE);
    EXPECT_EQ(parser.get_vici_answer().get_size(), 0);

    parser.set_conn_registered(nullptr);
}

/**
 * Objective: Verify that callback function for the event will run correctly.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserEventCB)
{
    ViciStreamParser_EnO parser(m_vici_api);
    FakeCalls fakeCalls;

    std::string testEvent = "TestEvent";
    vici_res_t* testRes = (vici_res_t*)0x100;

    fakeCalls.m_data_cb.m_section = &(parser.get_vici_section());
    fakeCalls.m_data_cb.m_vici_api  = &m_vici_api;

    ON_CALL(m_vici_api, parse_cb(_, _, _, _, _))
            .WillByDefault(Invoke(&fakeCalls, &FakeCalls::parse_cb_data_cb));

    EXPECT_CALL(m_vici_api, parse_cb(
                        Eq(testRes),
                        Eq(ViciStreamParser_EnO::get_parse_section_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_key_value_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_list_item_addr()),
                        NotNull()));

    parser.call_event_cb(&parser, (char*)testEvent.c_str(), testRes);

    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::OK);
}

/**
 * Objective: Verify that callback function for the event will set the correct
 * status if an error occurs.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserEventCBParseError)
{
    ViciStreamParser_EnO parser(m_vici_api);

    std::string testEvent = "TestEvent";
    vici_res_t* testRes = (vici_res_t*)0x100;

    EXPECT_CALL(m_vici_api, parse_cb(
                        Eq(testRes),
                        Eq(ViciStreamParser_EnO::get_parse_section_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_key_value_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_list_item_addr()),
                        NotNull()))
            .WillOnce(Return(-1));

    parser.call_event_cb(&parser, (char*)testEvent.c_str(), testRes);

    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::PARSE_ERR);
}

/**
 * Objective: Verify that callback function for the event will set the correct
 * status if the parser user data is sent as null.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserEventCBParseNull)
{
    ViciStreamParser_EnO parser(m_vici_api);

    std::string testEvent = "TestEvent";
    vici_res_t* testRes = (vici_res_t*)0x100;

    parser.call_event_cb(nullptr, (char*)testEvent.c_str(), testRes);

    EXPECT_EQ(parser.get_parse_status(), ipsec_ret::NOT_PARSE);
}

/**
 * Objective: Verify that callback function to parse a section
 * will run correctly.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserSectionParse)
{
    ViciStreamParser_EnO parser(m_vici_api);

    ViciStreamParser::DataCB dataCB;
    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string newName = "New_Section";
    ViciSection& section = parser.get_vici_section();

    dataCB.m_section = &section;
    dataCB.m_vici_api  = &m_vici_api;

    EXPECT_CALL(m_vici_api, parse_cb(
                        Eq(testRes),
                        Eq(ViciStreamParser_EnO::get_parse_section_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_key_value_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_list_item_addr()),
                        Eq((&dataCB))))
            .WillOnce(Return(0));

    EXPECT_EQ(parser.call_parse_section(
                                        &dataCB,
                                        testRes,
                                        (char*)newName.c_str()),
                                 0);

    ViciSection* subSection =
            reinterpret_cast<ViciSection*>(section.get_item(newName));

    ASSERT_NE(subSection, nullptr);
    EXPECT_EQ(dataCB.m_section, subSection);
    EXPECT_EQ(dataCB.m_section->get_name().compare(newName), 0);
    EXPECT_EQ(section.get_size(), 1);
}

/**
 * Objective: Verify that callback function to parse a section
 * will return correctly if data cb object is null.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserSectionParseNullDataCB)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string newName = "New_Section";
    ViciSection& section = parser.get_vici_section();

    EXPECT_EQ(parser.call_parse_section(
                                        nullptr,
                                        testRes,
                                        (char*)newName.c_str()),
                                 -1);

    EXPECT_EQ(section.get_size(), 0);
}

/**
 * Objective: Verify that callback function to parse a key value
 * will run correctly.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserKeyValueParse)
{
    ViciStreamParser_EnO parser(m_vici_api);

    ViciStreamParser::DataCB dataCB;
    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string newKey = "New_Key";
    std::string newValue = "New_Value";
    ViciSection& section = parser.get_vici_section();

    dataCB.m_section = &section;
    dataCB.m_vici_api  = &m_vici_api;

    EXPECT_CALL(m_vici_api, parse_cb(
                        Eq(testRes),
                        Eq(ViciStreamParser_EnO::get_parse_section_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_key_value_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_list_item_addr()),
                        Eq((&dataCB))))
            .WillOnce(Return(0));

    EXPECT_EQ(parser.call_parse_key_value(
                                          &dataCB,
                                          testRes,
                                          (char*)newKey.c_str(),
                                          (void*)newValue.c_str(),
                                          (int)newValue.size()),
                                 0);

    ViciValue* viciValue =
            reinterpret_cast<ViciValue*>(section.get_item(newKey));

    ASSERT_NE(viciValue, nullptr);
    EXPECT_EQ(viciValue->get_value().compare(newValue), 0);
    EXPECT_EQ(dataCB.m_section, (&section));
    EXPECT_EQ(section.get_size(), 1);
}

/**
 * Objective: Verify that callback function to parse a key value
 * will return correctly if data cb object is null.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserKeyValueParseNullDataCB)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string newKey = "New_Key";
    std::string newValue = "New_Value";
    ViciSection& section = parser.get_vici_section();

    EXPECT_EQ(parser.call_parse_key_value(
                                          nullptr,
                                          testRes,
                                          (char*)newKey.c_str(),
                                          (void*)newValue.c_str(),
                                          (int)newValue.size()),
                                 -1);

    EXPECT_EQ(section.get_size(), 0);
}

/**
 * Objective: Verify that callback function to parse a list item
 * will run correctly.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserListItemParse)
{
    ViciStreamParser_EnO parser(m_vici_api);

    ViciStreamParser::DataCB dataCB;
    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string newList = "New_List";
    std::string newValue = "New_Value";
    ViciSection& section = parser.get_vici_section();

    dataCB.m_section = &section;
    dataCB.m_vici_api  = &m_vici_api;

    EXPECT_CALL(m_vici_api, parse_cb(
                        Eq(testRes),
                        Eq(ViciStreamParser_EnO::get_parse_section_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_key_value_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_list_item_addr()),
                        Eq((&dataCB))))
            .WillOnce(Return(0));

    EXPECT_EQ(parser.call_parse_list_item(
                                          &dataCB,
                                          testRes,
                                          (char*)newList.c_str(),
                                          (void*)newValue.c_str(),
                                          (int)newValue.size()),
                                 0);

    ViciList* viciList =
            reinterpret_cast<ViciList*>(section.get_item(newList));

    ASSERT_NE(viciList, nullptr);
    EXPECT_EQ(viciList->get_size(), 1);
    EXPECT_EQ(viciList->get_value(0).compare(newValue), 0);
    EXPECT_EQ(dataCB.m_section, (&section));
    EXPECT_EQ(section.get_size(), 1);
}

/**
 * Objective: Verify that callback function to parse a list item
 * will run correctly, if the list already exists.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserListItemParseListExists)
{
    ViciStreamParser_EnO parser(m_vici_api);

    ViciStreamParser::DataCB dataCB;
    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string currentList = "C_List";
    std::string currentValue = "C_Value";
    std::string newValue = "New_Value";

    ViciSection& section = parser.get_vici_section();

    ViciList* newViciList = new ViciList();
    newViciList->add_value(currentValue);

    section.set_item(currentList, newViciList);

    dataCB.m_section = &section;
    dataCB.m_vici_api  = &m_vici_api;

    EXPECT_CALL(m_vici_api, parse_cb(
                        Eq(testRes),
                        Eq(ViciStreamParser_EnO::get_parse_section_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_key_value_addr()),
                        Eq(ViciStreamParser_EnO::get_parse_list_item_addr()),
                        Eq((&dataCB))))
            .WillOnce(Return(0));

    EXPECT_EQ(parser.call_parse_list_item(
                                          &dataCB,
                                          testRes,
                                          (char*)currentList.c_str(),
                                          (void*)newValue.c_str(),
                                          (int)newValue.size()),
                                 0);

    ViciList* viciList =
            reinterpret_cast<ViciList*>(section.get_item(currentList));

    ASSERT_NE(viciList, nullptr);
    EXPECT_EQ(viciList->get_size(), 2);
    EXPECT_EQ(viciList->get_value(1).compare(newValue), 0);
    EXPECT_EQ(dataCB.m_section, (&section));
    EXPECT_EQ(section.get_size(), 1);
}

/**
 * Objective: Verify that callback function to parse a list item
 * will return correctly if data cb object is null.
 **/
TEST_F(ViciStreamParserTestSuite, TestViciStreamParserListItemParseNullDataCB)
{
    ViciStreamParser_EnO parser(m_vici_api);

    vici_res_t* testRes = (vici_res_t*)0x100;
    std::string newList = "New_List";
    std::string newValue = "New_Value";
    ViciSection& section = parser.get_vici_section();

    EXPECT_EQ(parser.call_parse_list_item(
                                          nullptr,
                                          testRes,
                                          (char*)newList.c_str(),
                                          (void*)newValue.c_str(),
                                          (int)newValue.size()),
                                 -1);

    EXPECT_EQ(section.get_size(), 0);
}