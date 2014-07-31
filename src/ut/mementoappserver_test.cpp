/**
 * @file mementoappserver_test.cpp
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

#include <string>
#include "gtest/gtest.h"

#include "sip_common.hpp"
#include "mockappserver.hpp"
#include "mementoappserver.h"
#include "mockloadmonitor.hpp"
#include "mock_call_list_store_processor.h"
#include "test_interposer.hpp"

using namespace std;
using testing::InSequence;
using testing::Return;
using ::testing::_;
using ::testing::StrictMock;

/// Fixture for MementoAppServerTest.
class MementoAppServerTest : public SipCommonTest
{
public:
  static void SetUpTestCase()
  {
    SipCommonTest::SetUpTestCase();
    _helper = new MockAppServerTsxHelper();
    _clsp = new MockCallListStoreProcessor();

    cwtest_completely_control_time();
  }

  static void TearDownTestCase()
  {
    cwtest_reset_time();

    delete _clsp; _clsp = NULL;
    delete _helper; _helper = NULL;
    SipCommonTest::TearDownTestCase();
  }

  MementoAppServerTest() : SipCommonTest()
  {
  }

  ~MementoAppServerTest()
  {
  }

  static MockAppServerTsxHelper* _helper;
  static MockCallListStoreProcessor* _clsp;
};

MockAppServerTsxHelper* MementoAppServerTest::_helper = NULL;
MockCallListStoreProcessor* MementoAppServerTest::_clsp = NULL;

namespace MementoAS
{
class Message
{
public:
  string _method;
  string _toscheme;
  string _status;
  string _from;
  string _fromdomain;
  string _to;
  string _todomain;
  string _route;
  string _extra;

  Message() :
    _method("INVITE"),
    _toscheme("sip"),
    _status("200 OK"),
    _from("6505551000"),
    _fromdomain("homedomain"),
    _to("6505551234"),
    _todomain("homedomain"),
    _route(""),
    _extra("")
  {
  }

  string get_request();
  string get_response();
};
}

string MementoAS::Message::get_request()
{
  char buf[16384];

  // The remote target.
  string target = string(_toscheme).append(":").append(_to);
  if (!_todomain.empty())
  {
    target.append("@").append(_todomain);
  }

  int n = snprintf(buf, sizeof(buf),
                   "%1$s %4$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213;branch=z9hG4bK0123456789abcdef\r\n"
                   "From: Alice <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: Bob <%4$s>\r\n"
                   "%5$s"
                   "%6$s"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "Content-Length: 0\r\n\r\n",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ target.c_str(),
                   /*  5 */ _route.empty() ? "" : string(_route).append("\r\n").c_str(),
                   /*  6 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

string MementoAS::Message::get_response()
{
  char buf[16384];

  // The remote target.
  string target = string(_toscheme).append(":").append(_to);
  if (!_todomain.empty())
  {
    target.append("@").append(_todomain);
  }

  int n = snprintf(buf, sizeof(buf),
                   "SIP/2.0 %1$s\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213;branch=z9hG4bK0123456789abcdef\r\n"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <sip:%4$s@%5$s>\r\n"
                   "%6$s"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %7$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "Content-Length: 0\r\n\r\n",
                   /*  1 */ _status.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ _to.c_str(),
                   /*  5 */ _todomain.c_str(),
                   /*  6 */ _route.empty() ? "" : string(_route).append("\r\n").c_str(),
                   /*  7 */ _method.c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

using MementoAS::Message;

// Test creation and destruction of the MementoAppServer objects
TEST_F(MementoAppServerTest, CreateMementoAppServer)
{
  // Create a MementoAppServer object
  std::string home_domain = "home.domain";
  MementoAppServer* mas = new MementoAppServer("memento",
                                               home_domain,
                                               0,
                                               25,
                                               604800);

  // Test creating an app server transaction with an invalid method -
  // it shouldn't be created.
  Message msg;
  msg._method = "OPTIONS";
  pjsip_msg* req = parse_msg(msg.get_request());
  MementoAppServerTsx* mast = (MementoAppServerTsx*)mas->get_app_tsx(_helper, req);
  EXPECT_TRUE(mast == NULL);

  // Try with a valid method (Invite or Bye). This creates the application server
  // transaction
  msg._method = "INVITE";
  req = parse_msg(msg.get_request());
  mast = (MementoAppServerTsx*)mas->get_app_tsx(_helper, req);
  EXPECT_TRUE(mast != NULL);

  delete mast;
  delete mas;
}

// Test the mainline case for an incoming call
TEST_F(MementoAppServerTest, MainlineIncomingTest)
{
  Message msg;
  std::string service_name = "memento";
  std::string home_domain = "home.domain";
  MementoAppServerTsx as_tsx(_helper, _clsp, service_name, home_domain);

  // Message is parsed successfully. The on_initial_request method
  // adds a Record-Route header.
  EXPECT_CALL(*_helper, add_to_dialog(_));
  EXPECT_CALL(*_helper, send_request(_)).WillOnce(Return(0));
  as_tsx.on_initial_request(parse_msg(msg.get_request()));

  // On a 200 OK response the as_tsx generates a BEGIN call fragment
  // writes it to the call list store
  time_t currenttime;
  time(&currenttime);
  tm* ct = localtime(&currenttime);
  std::string answer_timestamp = as_tsx.create_formatted_timestamp(ct, "%Y-%m-%dT%H:%M:%S");

  std::string xml = std::string("<to>\n\t<uri>sip:6505551234@homedomain</uri>\n</to>\n<from>\n\t<uri>sip:6505551000@homedomain</uri>\n\t<name>Alice</name>\n</from>\n<outgoing>1</outgoing>\n<start-time>").append(answer_timestamp).append("</start-time>\n<answered>1</answered>\n<answer-time>").append(answer_timestamp).append("</answer-time>\n\n");
  std::string impu = "sip:6505551234@homedomain";
  EXPECT_CALL(*_clsp, write_call_list_entry(impu, _, _, CallListStore::CallFragment::Type::BEGIN, xml, _));
  EXPECT_CALL(*_helper, send_response(_));
  pjsip_msg* rsp = parse_msg(msg.get_response());
  as_tsx.on_response(rsp, 0);

  // On a BYE in dialog request the as_tsx generates an END call
  // fragment and writes it to the call list store.
//  TODO temporaily commented out while the dialog id is being fixed.
//  msg._route = "Route: <sip:123-456_789@memento.homedomain>";
//  xml = std::string("<end-time>").append(answer_timestamp).append("</end-time>\n\n");
//  EXPECT_CALL(*_helper, send_request(_)).WillOnce(Return(0));
//  EXPECT_CALL(*_clsp, write_call_list_entry(_, _, _, _, _, _));
//  EXPECT_CALL(*_clsp, write_call_list_entry(_, _, _, CallListStore::CallFragment::Type::END, xml, _));
//  as_tsx.on_in_dialog_request(parse_msg(msg.get_request()));
}

// Test the mainline case for an outgoing call
TEST_F(MementoAppServerTest, MainlineOutgoingTest)
{
  Message msg;
  std::string service_name = "memento";
  std::string home_domain = "home.domain";
  MementoAppServerTsx as_tsx(_helper, _clsp, service_name, home_domain);

  // Message is parsed successfully. The on_initial_request method
  // adds a Record-Route header.
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "P-Asserted-Identity: <sip:6505551234@homedomain;orig>";
  EXPECT_CALL(*_helper, add_to_dialog(_));
  EXPECT_CALL(*_helper, send_request(_)).WillOnce(Return(0));
  as_tsx.on_initial_request(parse_msg(msg.get_request()));

  // On a 200 OK response the as_tsx generates a BEGIN call fragment
  // writes it to the call list store
  time_t currenttime;
  time(&currenttime);
  tm* ct = localtime(&currenttime);
  std::string answer_timestamp = as_tsx.create_formatted_timestamp(ct, "%Y-%m-%dT%H:%M:%S");

  std::string xml = std::string("<to>\n\t<uri>sip:6505551234@homedomain</uri>\n</to>\n<from>\n\t<uri>sip:6505551000@homedomain</uri>\n\t<name>Alice</name>\n</from>\n<outgoing>0</outgoing>\n<start-time>").append(answer_timestamp).append("</start-time>\n<answered>1</answered>\n<answer-time>").append(answer_timestamp).append("</answer-time>\n\n");
  std::string impu = "sip:6505551234@homedomain";
  EXPECT_CALL(*_clsp, write_call_list_entry(impu, _, _, CallListStore::CallFragment::Type::BEGIN, xml, _));
  EXPECT_CALL(*_helper, send_response(_));
  pjsip_msg* rsp = parse_msg(msg.get_response());
  as_tsx.on_response(rsp, 0);

  // Send in another response - this should return straightaway
  as_tsx.on_response(rsp, 0);
}

// Test that a non final response doesn't trigger writes to cassandra
TEST_F(MementoAppServerTest, OnNonFinalResponse)
{
  Message msg;
  std::string service_name = "memento";
  std::string home_domain = "home.domain";
  MementoAppServerTsx as_tsx(_helper, _clsp, service_name, home_domain);

  EXPECT_CALL(*_helper, add_to_dialog(_));
  EXPECT_CALL(*_helper, send_request(_)).WillOnce(Return(0));
  as_tsx.on_initial_request(parse_msg(msg.get_request()));

  msg._status = "100 Trying";
  pjsip_msg* rsp = parse_msg(msg.get_response());
  EXPECT_CALL(*_helper, send_response(_));
  as_tsx.on_response(rsp, 0);
}

// Test that an error response triggers a REJECTED call fragment.
TEST_F(MementoAppServerTest, OnErrorResponse)
{
  Message msg;
  std::string service_name = "memento";
  std::string home_domain = "home.domain";
  MementoAppServerTsx as_tsx(_helper, _clsp, service_name, home_domain);

  EXPECT_CALL(*_helper, add_to_dialog(_));
  EXPECT_CALL(*_helper, send_request(_)).WillOnce(Return(0));
  as_tsx.on_initial_request(parse_msg(msg.get_request()));

  msg._status = "404 Not Found";
  EXPECT_CALL(*_clsp, write_call_list_entry(_, _, _, CallListStore::CallFragment::Type::REJECTED, _, _));
  EXPECT_CALL(*_helper, send_response(_));
  pjsip_msg* rsp = parse_msg(msg.get_response());
  as_tsx.on_response(rsp, 0);
}
