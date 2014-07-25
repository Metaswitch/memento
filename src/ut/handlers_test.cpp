/**
 * @file handlers_test.cpp UT for Handlers module.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */
#include "test_utils.hpp"
#include "test_interposer.hpp"

#include "mockhttpstack.hpp"
#include "mock_call_list_store.h"
#include "handlers.h"
#include "localstore.h"

using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArgs;
using ::testing::NiceMock;
using ::testing::StrictMock;
using ::testing::Mock;

// Fixture for HandlersTest.
class HandlersTest : public testing::Test
{
public:
  static MockHttpStack* _httpstack;
  LocalStore* _store;
  AuthStore* _auth_store;
  MockCallListStore* _call_store;
  CallListHandler::Config* _cfg;


  HandlersTest()
  {
    _store = new LocalStore();
    _auth_store = new AuthStore(_store, 20);
    _call_store = new MockCallListStore();
    _cfg = new CallListHandler::Config(_auth_store, NULL, _call_store, "localhost");

  }
  virtual ~HandlersTest()
  {
    delete _auth_store;
    delete _store;
    delete _call_store;
    delete _cfg;
  }

  static void SetUpTestCase()
  {
    _httpstack = new MockHttpStack();
    cwtest_completely_control_time();
  }

  static void TearDownTestCase()
  {
    cwtest_reset_time();

    delete _httpstack; _httpstack = NULL;
  }
};

MockHttpStack* HandlersTest::_httpstack = NULL;

TEST_F(HandlersTest, Mainline)
{
  std::vector<CallListStore::CallFragment> records;
  CallListStore::CallFragment record1;
  CallListStore::CallFragment record2;
  CallListStore::CallFragment record3;
  CallListStore::CallFragment record4;
  record1.type = CallListStore::CallFragment::Type::BEGIN;
  record1.id = "a";
  record1.contents = (
    "<to>"
      "<URI>alice@example.com</URI>"
      "<name>Alice Adams</name>"
    "</to>"
    "<from>"
      "<URI>bob@example.com</URI>"
      "<name>Bob Barker</name>"
    "</from>"
    "<answered>1</answered>"
    "<outgoing>1</outgoing>"
    "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>");
  record2.type = CallListStore::CallFragment::Type::END;
  record2.id = "a";
  record2.contents = "<end-time>2002-05-30T09:35:00</end-time>";
  record3.type = CallListStore::CallFragment::Type::REJECTED;
  record3.id = "b";
  record3.contents = (
    "<to>"
      "<URI>alice@example.net</URI>"
      "<name>Alice Adams</name>"
    "</to>"
    "<from>"
      "<URI>bob@example.net</URI>"
      "<name>Bob Barker</name>"
    "</from>"
    "<answered>0</answered>"
    "<outgoing>1</outgoing>"
    "<start-time>2002-05-30T09:30:10</start-time>");
  records.push_back(record1);
  records.push_back(record3);
  records.push_back(record2);
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(records), Return(CassandraStore::ResultCode::OK)));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  handler->respond_when_authenticated();

  EXPECT_EQ((
              "<call-list><calls>"
                "<call>"
                  "<to>"
                    "<URI>alice@example.com</URI>"
                    "<name>Alice Adams</name>"
                  "</to>"
                  "<from>"
                    "<URI>bob@example.com</URI>"
                    "<name>Bob Barker</name>"
                  "</from>"
                  "<answered>1</answered>"
                  "<outgoing>1</outgoing>"
                  "<start-time>2002-05-30T09:30:10</start-time>"
                  "<answer-time>2002-05-30T09:30:20</answer-time>"
                  "<end-time>2002-05-30T09:35:00</end-time>"
                "</call>"
                "<call>"
                  "<to>"
                    "<URI>alice@example.net</URI>"
                    "<name>Alice Adams</name>"
                  "</to>"
                  "<from>"
                    "<URI>bob@example.net</URI>"
                    "<name>Bob Barker</name>"
                  "</from>"
                  "<answered>0</answered>"
                  "<outgoing>1</outgoing>"
                  "<start-time>2002-05-30T09:30:10</start-time>"
                "</call>"
              "</calls></call-list>"),
            req.content());
  delete handler;
}

TEST_F(HandlersTest, DuplicatedBegin)
{
  std::vector<CallListStore::CallFragment> records;
  CallListStore::CallFragment record1;
  CallListStore::CallFragment record2;
  record1.type = CallListStore::CallFragment::Type::BEGIN;
  record1.id = "a";
  record1.contents = (
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>1</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>");
  record2.type = CallListStore::CallFragment::Type::END;
  record2.id = "a";
  record2.contents = "<end-time>2002-05-30T09:35:00</end-time>";
  records.push_back(record1);
  records.push_back(record1);
  records.push_back(record2);
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(records), Return(CassandraStore::ResultCode::OK)));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  handler->respond_when_authenticated();

  EXPECT_EQ(  record1.contents = ("<call-list><calls><call>"
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>1</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>"
    "<end-time>2002-05-30T09:35:00</end-time>"
    "</call></calls></call-list>")
    , req.content());
  delete handler;
}

TEST_F(HandlersTest, DuplicatedEnd)
{
  std::vector<CallListStore::CallFragment> records;
  CallListStore::CallFragment record1;
  CallListStore::CallFragment record2;
  record1.type = CallListStore::CallFragment::Type::BEGIN;
  record1.id = "a";
  record1.contents = (
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>1</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>");
  record2.type = CallListStore::CallFragment::Type::END;
  record2.id = "a";
  record2.contents = "<end-time>2002-05-30T09:35:00</end-time>";
  records.push_back(record1);
  records.push_back(record2);
  records.push_back(record2);
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(records), Return(CassandraStore::ResultCode::OK)));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  handler->respond_when_authenticated();

  EXPECT_EQ(  record1.contents = ("<call-list><calls><call>"
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>1</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>"
    "<end-time>2002-05-30T09:35:00</end-time>"
    "</call></calls></call-list>")
    , req.content());
  delete handler;
}

TEST_F(HandlersTest, DuplicatedRejected)
{
  std::vector<CallListStore::CallFragment> records;
  CallListStore::CallFragment record1;
  CallListStore::CallFragment record2;
  record1.type = CallListStore::CallFragment::Type::REJECTED;
  record1.id = "a";
  record1.contents = (
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>0</answered>"
      "<outgoing>1</outgoing>"
    "<start-time>2002-05-30T09:30:10</start-time>");
  records.push_back(record1);
  records.push_back(record1);
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(records), Return(CassandraStore::ResultCode::OK)));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  handler->respond_when_authenticated();

  EXPECT_EQ(  record1.contents = ("<call-list><calls><call>"
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>0</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "</call></calls></call-list>")
    , req.content());
  delete handler;
}


TEST_F(HandlersTest, WrongOrder)
{
  std::vector<CallListStore::CallFragment> records;
  CallListStore::CallFragment record1;
  CallListStore::CallFragment record2;
  record1.type = CallListStore::CallFragment::Type::BEGIN;
  record1.id = "a";
  record1.contents = (
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>1</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>");
  record2.type = CallListStore::CallFragment::Type::END;
  record2.id = "a";
  record2.contents = "<end-time>2002-05-30T09:35:00</end-time>";
  records.push_back(record2);
  records.push_back(record1);
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(records), Return(CassandraStore::ResultCode::OK)));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  handler->respond_when_authenticated();

  EXPECT_EQ(  record1.contents = ("<call-list><calls>"
    "</calls></call-list>")
    , req.content());
  delete handler;
}

TEST_F(HandlersTest, MissingEnd)
{
  std::vector<CallListStore::CallFragment> records;
  CallListStore::CallFragment record1;
  record1.type = CallListStore::CallFragment::Type::BEGIN;
  record1.id = "a";
  record1.contents = (
    "<to>"
        "<URI>alice@example.com</URI>"
        "<name>Alice Adams</name>"
      "</to>"
      "<from>"
        "<URI>bob@example.com</URI>"
        "<name>Bob Barker</name>"
      "</from>"
      "<answered>1</answered>"
      "<outgoing>1</outgoing>"
      "<start-time>2002-05-30T09:30:10</start-time>"
    "<answer-time>2002-05-30T09:30:20</answer-time>");
  records.push_back(record1);
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(records), Return(CassandraStore::ResultCode::OK)));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  handler->respond_when_authenticated();

  EXPECT_EQ("<call-list><calls></calls></call-list>", req.content());
  delete handler;
}

TEST_F(HandlersTest, NotFound)
{
  MockHttpStack::Request req(_httpstack, "/", "digest", "");

  CallListHandler* handler = new CallListHandler(req, _cfg, 0);

  EXPECT_CALL(*_call_store, get_call_fragments_sync(_, _, _))
    .WillOnce(Return(CassandraStore::ResultCode::NOT_FOUND));

  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  handler->respond_when_authenticated();

  EXPECT_EQ("", req.content());
  delete handler;
}
