/**
 * @file httpdigestauthenticate_test.cpp
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
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "httpdigestauthenticate.h"
#include "localstore.h"
#include "authstore.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "fakehomesteadconnection.hpp"

using namespace std;

/// Fixture for HTTPDigestAuthenticateTest.
class HTTPDigestAuthenticateTest : public ::testing::Test
{
  HTTPDigestAuthenticateTest()
  {
    _local_data_store = new LocalStore();
    _auth_store = new AuthStore(_local_data_store, 300);
    _hc = new FakeHomesteadConnection();
    _auth_mod = new HTTPDigestAuthenticate(_auth_store, _hc, "home.domain");
    _response = new HTTPDigestAuthenticate::Response();
  }

  virtual ~HTTPDigestAuthenticateTest()
  {
    delete _response; _response = NULL;
    delete _auth_mod; _auth_mod = NULL;
    delete _hc; _hc = NULL;
    delete _auth_store; _auth_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
  }

  LocalStore* _local_data_store;
  AuthStore* _auth_store;
  FakeHomesteadConnection* _hc;
  HTTPDigestAuthenticate* _auth_mod;
  HTTPDigestAuthenticate::Response* _response;
};

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_NoAuthHeader)
{
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with no auth header.
  std::string auth_header = "";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_NoAuthHeaderInvalidIMPU)
{
  // set the _impu
  _auth_mod->set_members("sips:1231231231@home.domain", "GET", "", 0);

  // Test with no auth header and an invalid IMPU.
  std::string auth_header = "";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(_auth_mod->_impi, "");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_MinimalAuthHeader)
{
  // set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with a minimal auth header.
  std::string auth_header = "Digest username=1231231231@home.domain";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);
  ASSERT_EQ(rc, 200);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_FullAuthHeader)
{
  // set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with a full auth header.
  std::string auth_header = "Digest username=1231231231@home.domain,realm=home.domain,nonce=nonce,uri=/org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml,qop=auth,nc=00001,cnonce=cnonce,response=response,opaque=opaque";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_info, true);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_InvalidAuthHeaderNoDigest)
{
  // set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with an auth header that doesn't have Digest credentials.
  std::string auth_header = "Not Digest";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(_auth_mod->_impi, "");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_InvalidAuthHeaderNoUsername)
{
  // set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with an auth header that doesn't have a username
  std::string auth_header = "Digest realm=home.domain";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(_auth_mod->_impi, "");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_IncompleteAuthHeader)
{
  // set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with an incomplete auth header
  std::string auth_header = "Digest username=1231231231,realm=home.domain,nc=00001";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(_auth_mod->_impi, "");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_InvalidAuthHeaderQopNotAuth)
{
  // Test with an auth header where qop isn't auth
  std::string auth_header = "Digest username=1231231231,realm=home.domain,nonce=nonce,uri=/org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml,qop=auth-int,nc=00001,cnonce=cnonce,response=response,opaque=opaque";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 400);
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_MinimalAuthHeaderWithQuotes)
{
  // set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "", 0);

  // Test with an auth header with quotes
  std::string auth_header = "Digest username=\"1231231231@home.domain\"";
  bool auth_info = false;
  long rc = _auth_mod->check_auth_header(auth_header, auth_info, _response);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_info, false);
}

TEST_F(HTTPDigestAuthenticateTest, RequestStoreDigest)
{
  std::vector<std::string> test;
  test.push_back("digest_1");
  test.push_back("realm");
  _hc->set_result("/impi/1231231231%40home.domain/av?impu=sip%3A1231231231%40home.domain", test);

  // set the _impu/_impi
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);

  // Request the digest.
  std::string www_auth_header;
  long rc = _auth_mod->request_digest_and_store(www_auth_header, false, _response);

  ASSERT_EQ(rc, 401);
}

TEST_F(HTTPDigestAuthenticateTest, RequestStoreDigest_Stale)
{
  std::vector<std::string> test;
  test.push_back("digest_1");
  test.push_back("realm");
  test[1] = "realm";
  _hc->set_result("/impi/1231231231%40home.domain/av?impu=sip%3A1231231231%40home.domain", test);

  // set the _impu/_impi
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);

  // Request the digest. The header will contain the stale parameter
  std::string www_auth_header;
  long rc = _auth_mod->request_digest_and_store(www_auth_header, true, _response);

  ASSERT_EQ(rc, 401);
 // ASSERT_EQ(_auth_mod->_header, "");
}

TEST_F(HTTPDigestAuthenticateTest, RetrieveDigest_NotPresent)
{
  std::vector<std::string> test;
  test.push_back("digest_1");
  test.push_back("realm");
  _hc->set_result("/impi/1231231231%40home.domain/av?impu=sip%3A1231231231%40home.domain", test);

  // set the _impu/_impi
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque");

  // Test with a minimal auth header.
  std::string www_auth_header;
  long rc = _auth_mod->retrieve_digest_from_store(www_auth_header, _response);

  ASSERT_EQ(rc, 401);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");
}

TEST_F(HTTPDigestAuthenticateTest, RetrieveDigest_Present)
{
  std::vector<std::string> test;
  test.push_back("digest_1");
  test.push_back("realm");
  _hc->set_result("/impi/1231231231%40home.domain/av?impu=sip%3A1231231231%40home.domain", test);

  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_impu = "sip:1231231231@home.domain";

  _auth_store->set_digest("1231231231@home.domain", "nonce", digest, 0);

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque");

  // Run through retrieving the digest. This will result in a 403 it won't match.
  std::string www_auth_header;
  long rc = _auth_mod->retrieve_digest_from_store(www_auth_header, _response);

  ASSERT_EQ(rc, 403);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");

  delete digest;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_InvalidOpaque)
{
  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_impu = "sip:1231231231@home.domain";

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque2");

  // Run through check if matches. This will reject the request as the opaque value
  // is wrong
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");

  delete digest; digest = NULL;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_InvalidRealm)
{
  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_impu = "sip:1231231231@home.domain";

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain2","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque");

  // Run through check if matches. This will reject the request as the realm value
  // is wrong
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");

  delete digest; digest = NULL;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_Valid)
{
  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_impu = "sip:1231231231@home.domain";

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","242c99c1e20618147c6a325c09720664","opaque");

  // Run through check if matches - should pass
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");

  delete digest; digest = NULL;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_Stale)
{
  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_nonce_count = 2;
  digest->_impu = "sip:1231231231@home.domain";

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","242c99c1e20618147c6a325c09720664","opaque");

  // Run through check if matches - should pass, but the nonce is stale
  // The request will then fail as it can't get the digest from Homestead
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  ASSERT_EQ(rc, 404);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");

  delete digest; digest = NULL;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_WrongIMPU)
{
  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_impu = "sip:1231231232@home.domain";

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","242c99c1e20618147c6a325c09720664","opaque");

  // Run through check if matches - should pass, but the impu is different to the
  // stored impu
  // The request will then fail as it can't get the digest from Homestead
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  ASSERT_EQ(rc, 404);
  ASSERT_EQ(_auth_mod->_impi, "1231231231@home.domain");

  delete digest; digest = NULL;
}
