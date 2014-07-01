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
#include "mockhttpconnection.hpp"
#include "handlers.h"
#include "fakelogger.hpp"
#include "homesteadconnection.h"

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
  FakeLogger _log;
  static MockHttpStack* _httpstack;
  static MockHttpConnection* _mock_http_conn;
  static HomesteadConnection* _homestead_conn;

  HandlersTest() {}
  virtual ~HandlersTest()
  {
//    Mock::VerifyAndClear(_httpstack);
  }

  static void SetUpTestCase()
  {
    _httpstack = new MockHttpStack();
    _mock_http_conn = new MockHttpConnection();
    _homestead_conn = new HomesteadConnection(_mock_http_conn);

    cwtest_completely_control_time();
  }

  static void TearDownTestCase()
  {
    cwtest_reset_time();

    delete _httpstack; _httpstack = NULL;
    delete _homestead_conn; _homestead_conn = NULL;
  }
};

MockHttpStack* HandlersTest::_httpstack = NULL;
MockHttpConnection* HandlersTest::_mock_http_conn = NULL;
HomesteadConnection* HandlersTest::_homestead_conn = NULL;

//
// Ping test
//
TEST_F(HandlersTest, SimpleMainline)
{
  MockHttpStack::Request req(_httpstack, "/", "ping");
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  PingHandler* handler = new PingHandler(req, 0);
  handler->run();
  EXPECT_EQ("OK", req.content());
}

