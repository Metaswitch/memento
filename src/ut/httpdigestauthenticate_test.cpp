/**
 * @file authstore_test.cpp 
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

/// Fixture for RegStoreTest.
class HTTPDigestAuthenticateTest : public ::testing::Test
{
  HTTPDigestAuthenticateTest()
  {
  }

  virtual ~HTTPDigestAuthenticateTest()
  {
  }

  static void SetUpTestCase()
  {
  }
};


TEST_F(HTTPDigestAuthenticateTest, CreateAndDestroy)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();
  
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_NoAuthHeader)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Create the auth_mod and 
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";

  // Test with no auth header.  
  std::string auth_header = "";
  long rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

// TODO
/*TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_NoAuthHeaderInvalidIMPU)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sips:1231231231@home.domain";

  // Test with no auth header.
  std::string auth_header = "";
  long rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}*/

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_MinimalAuthHeader)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";

  // Test with a minimal auth header.
  std::string auth_header = "Digest username=1231231231,realm=home.domain";
  long rc = auth_mod->check_auth_info(auth_header);
  ASSERT_EQ(rc, 200);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_FullAuthHeader)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";

  // Test with no auth header.
  std::string auth_header = "Digest username=1231231231,realm=home.domain,nonce=nonce,uri=/org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml,qop=auth,nc=00001,cnonce=cnonce,response=response,opaque=opaque";
  long rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, true);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_InvalidAuthHeader)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";

  // Test with no auth header.
  std::string auth_header = "Not Digest";
  long rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(auth_mod->_impi, "");
  ASSERT_EQ(auth_mod->_auth_info, false);

  auth_header = "Digest realm=home.domain";
  rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(auth_mod->_impi, "");
  ASSERT_EQ(auth_mod->_auth_info, false);

  auth_header = "Digest username=1231231231";
  rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(auth_mod->_impi, "");
  ASSERT_EQ(auth_mod->_auth_info, false);

  auth_header = "Digest username=1231231231,realm=home.domain,nc=00001";
  rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(auth_mod->_impi, "");
  ASSERT_EQ(auth_mod->_auth_info, false);

  auth_header = "Digest username=1231231231,realm=home.domain,nonce=nonce,uri=/org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml,qop=auth-int,nc=00001,cnonce=cnonce,response=response,opaque=opaque";
  rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 400);

  auth_header = "Digest username=1231231231,realm=not.home.domain,nonce=nonce,uri=/org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml,qop=auth,nc=00001,cnonce=cnonce,response=response,opaque=opaque";
  rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 400);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

// TODO
/*TEST_F(HTTPDigestAuthenticateTest, CheckAuthInfo_MinimalAuthHeaderWithQuotes)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";

  // Test with no auth header.
  std::string auth_header = "Digest username=1231231231,realm=home.domain";
  long rc = auth_mod->check_auth_info(auth_header);

  ASSERT_EQ(rc, 200);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}*/

TEST_F(HTTPDigestAuthenticateTest, RequestStoreDigest)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();
//                  /impi/1231231231%40home.domain/digest?public_id=sip%3A1231231231%40home.domain
  hc->set_result("/impi/1231231231%40home.domain/digest?public_id=sip%3A1231231231%40home.domain", "digest_1");
  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";
  auth_mod->_impi = "1231231231@home.domain";

  // Test with a minimal auth header.
  long rc = auth_mod->request_store_digest(false);

  ASSERT_EQ(rc, 401);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, RequestStoreDigest_Stale)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();
//                  /impi/1231231231%40home.domain/digest?public_id=sip%3A1231231231%40home.domain
  hc->set_result("/impi/1231231231%40home.domain/digest?public_id=sip%3A1231231231%40home.domain", "digest_1");
  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";
  auth_mod->_impi = "1231231231@home.domain";

  // Test with a minimal auth header.
  long rc = auth_mod->request_store_digest(true);

  ASSERT_EQ(rc, 401);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, RetrieveDigest_NotPresent)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  hc->set_result("/impi/1231231231%40home.domain/digest?public_id=sip%3A1231231231%40home.domain", "digest_1");
//  auth_store->set_digest("1231231231@home.domain", "nonce", digest, 0);
  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";
  auth_mod->_impi = "1231231231@home.domain";
  auth_mod->_response = new HTTPDigestAuthenticate::Response("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque");

  // Test with a minimal auth header.
  long rc = auth_mod->retrieve_digest();

  ASSERT_EQ(rc, 401);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, RetrieveDigest_Present)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  hc->set_result("/impi/1231231231%40home.domain/digest?public_id=sip%3A1231231231%40home.domain", "digest_1");
  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";

  auth_store->set_digest("1231231231@home.domain", "nonce", digest, 0);
  
  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";
  auth_mod->_impi = "1231231231@home.domain";
  auth_mod->_response = new HTTPDigestAuthenticate::Response("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque");

  // Test with a minimal auth header.
  long rc = auth_mod->retrieve_digest();

  ASSERT_EQ(rc, 403);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

  delete digest;
  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_InvalidOpaque)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);
  FakeHomesteadConnection* hc = new FakeHomesteadConnection();

  // Write a digest to the store.
  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";

  // Create the auth_mod and
  HTTPDigestAuthenticate* auth_mod = new HTTPDigestAuthenticate(auth_store, hc, "home.domain");

  // Set the _impu
  auth_mod->_impu = "sip:1231231231@home.domain";
  auth_mod->_impi = "1231231231@home.domain";
  auth_mod->_response = new HTTPDigestAuthenticate::Response("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","response","opaque2");
  auth_mod->_digest = digest;

  // Test with a minimal auth header.
  long rc = auth_mod->check_if_matches();

  ASSERT_EQ(rc, 400);
  ASSERT_EQ(auth_mod->_impi, "1231231231@home.domain");
  ASSERT_EQ(auth_mod->_auth_info, false);

// Why is this causing segfauls?
//  delete digest;
  delete auth_mod;
  delete hc;
  delete auth_store;
  delete local_data_store;
}

