/**
 * @file httpdigestauthenticate_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
#include "fakecounter.h"
#include "mockauthstore.h"

using namespace std;
using testing::MatchesRegex;
using testing::Return;
using testing::_;

const SAS::TrailId DUMMY_TRAIL_ID = 0x1122334455667788;

/// Base class for the fixtures used to test the HttpDigestAuthenticate class.
class HTTPDigestAuthenticateTestBase : public ::testing::Test
{
  FakeCounter _auth_challenge_count;
  FakeCounter _auth_attempt_count;
  FakeCounter _auth_success_count;
  FakeCounter _auth_failure_count;
  FakeCounter _auth_stale_count;
  FakeHomesteadConnection* _hc;
  HTTPDigestAuthenticate* _auth_mod;
  HTTPDigestAuthenticate::Response* _response;

  HTTPDigestAuthenticateTestBase()
  {
    _hc = new FakeHomesteadConnection();
    _response = new HTTPDigestAuthenticate::Response();
    _auth_mod = NULL;
  }

  virtual ~HTTPDigestAuthenticateTestBase()
  {
    delete _response; _response = NULL;
    delete _hc; _hc = NULL;
  }
};

/// Test fixture that uses an auth store that is backed by a fake store.
class HTTPDigestAuthenticateTest : public HTTPDigestAuthenticateTestBase
{
  HTTPDigestAuthenticateTest()
  {
    _local_data_store = new LocalStore();
    _auth_store = new AuthStore(_local_data_store, 300);
    _auth_mod = new HTTPDigestAuthenticate(_auth_store,
                                           _hc,
                                           "home.domain",
                                           &_auth_challenge_count,
                                           &_auth_attempt_count,
                                           &_auth_success_count,
                                           &_auth_failure_count,
                                           &_auth_stale_count);
  }

  virtual ~HTTPDigestAuthenticateTest()
  {
    delete _auth_mod; _auth_mod = NULL;
    delete _auth_store; _auth_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
  }

  LocalStore* _local_data_store;
  AuthStore* _auth_store;
};

/// Test fixture that uses a mock auth store.
class HTTPDigestAuthenticateMockStoreTest : public HTTPDigestAuthenticateTestBase
{
  HTTPDigestAuthenticateMockStoreTest()
  {
    _auth_mod = new HTTPDigestAuthenticate(&_mock_auth_store,
                                           _hc,
                                           "home.domain",
                                           &_auth_challenge_count,
                                           &_auth_attempt_count,
                                           &_auth_success_count,
                                           &_auth_failure_count,
                                           &_auth_stale_count);
  }

  virtual ~HTTPDigestAuthenticateMockStoreTest()
  {
    delete _auth_mod; _auth_mod = NULL;
  }

  MockAuthStore _mock_auth_store;
  HTTPDigestAuthenticate* _auth_mod;
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

  EXPECT_THAT(www_auth_header,
              MatchesRegex("Digest realm=\"home\\.domain\",qop=\"auth\",nonce=\".*\",opaque=\".*\""));
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

  EXPECT_THAT(www_auth_header,
              MatchesRegex("Digest realm=\"home\\.domain\",qop=\"auth\",nonce=\".*\",opaque=\".*\",stale=TRUE"));
  ASSERT_EQ(rc, 401);
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
  // Write a digest to the store. This simulates the digest stored when the
  // unauthenticated request was received.
  AuthStore::Digest orig_digest;
  orig_digest._impi = "1231231231@home.domain";
  orig_digest._nonce = "nonce";
  orig_digest._ha1 = "123123123";
  orig_digest._opaque = "opaque";
  orig_digest._realm = "home.domain";
  orig_digest._impu = "sip:1231231231@home.domain";
  _auth_store->set_digest(orig_digest._impi, orig_digest._nonce, &orig_digest, DUMMY_TRAIL_ID);

  // Read the digest back.  This simulates the processing just before the
  // authenticated request is checked.
  AuthStore::Digest* digest;
  _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, digest, DUMMY_TRAIL_ID);

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
  // Write a digest to the store. This simulates the digest stored when the
  // unauthenticated request was received.
  AuthStore::Digest orig_digest;
  orig_digest._impi = "1231231231@home.domain";
  orig_digest._nonce = "nonce";
  orig_digest._ha1 = "123123123";
  orig_digest._opaque = "opaque";
  orig_digest._realm = "home.domain";
  orig_digest._impu = "sip:1231231231@home.domain";
  _auth_store->set_digest(orig_digest._impi, orig_digest._nonce, &orig_digest, DUMMY_TRAIL_ID);

  // Read the digest back.  This simulates the processing just before the
  // authenticated request is checked.
  AuthStore::Digest* digest;
  _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, digest, DUMMY_TRAIL_ID);

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

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_Valid_ReturnsOK)
{
  // Write a digest to the store. This simulates the digest stored when the
  // unauthenticated request was received.
  AuthStore::Digest orig_digest;
  orig_digest._impi = "1231231231@home.domain";
  orig_digest._nonce = "nonce";
  orig_digest._ha1 = "123123123";
  orig_digest._opaque = "opaque";
  orig_digest._realm = "home.domain";
  orig_digest._impu = "sip:1231231231@home.domain";
  _auth_store->set_digest(orig_digest._impi, orig_digest._nonce, &orig_digest, DUMMY_TRAIL_ID);

  // Read the digest back.  This simulates the processing just before the
  // authenticated request is checked.
  AuthStore::Digest* digest;
  _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, digest, DUMMY_TRAIL_ID);

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

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_Valid_UpdatesNonceCount)
{
  // Write a digest to the store. This simulates the digest stored when the
  // unauthenticated request was received.
  AuthStore::Digest orig_digest;
  orig_digest._impi = "1231231231@home.domain";
  orig_digest._nonce = "nonce";
  orig_digest._ha1 = "123123123";
  orig_digest._opaque = "opaque";
  orig_digest._realm = "home.domain";
  orig_digest._impu = "sip:1231231231@home.domain";
  _auth_store->set_digest(orig_digest._impi, orig_digest._nonce, &orig_digest, DUMMY_TRAIL_ID);

  // Read the digest back.  This simulates the processing just before the
  // authenticated request is checked.
  AuthStore::Digest* digest;
  _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, digest, DUMMY_TRAIL_ID);

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","242c99c1e20618147c6a325c09720664","opaque");

  // Run through check if matches - should pass
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  ASSERT_EQ(rc, 200);

  // Check that the digest's nonce count has been updated in the store.
  AuthStore::Digest* new_digest = NULL;
  Store::Status status = _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, new_digest, DUMMY_TRAIL_ID);
  EXPECT_EQ(Store::OK, status);
  EXPECT_EQ(2u, new_digest->_nonce_count);

  delete new_digest; new_digest = NULL;
  delete digest; digest = NULL;
}

TEST_F(HTTPDigestAuthenticateTest, CheckIfMatches_Stale)
{
  // Write a digest to the store. This simulates the digest stored when the
  // unauthenticated request was received.
  AuthStore::Digest orig_digest;
  orig_digest._impi = "1231231231@home.domain";
  orig_digest._nonce = "nonce";
  orig_digest._ha1 = "123123123";
  orig_digest._opaque = "opaque";
  orig_digest._realm = "home.domain";
  orig_digest._impu = "sip:1231231231@home.domain";
  orig_digest._nonce_count = 2; // Not equal to 1.
  _auth_store->set_digest(orig_digest._impi, orig_digest._nonce, &orig_digest, DUMMY_TRAIL_ID);

  // Read the digest back.  This simulates the processing just before the
  // authenticated request is checked.
  AuthStore::Digest* digest;
  _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, digest, DUMMY_TRAIL_ID);

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
  // Write a digest to the store. This simulates the digest stored when the
  // unauthenticated request was received.
  AuthStore::Digest orig_digest;
  orig_digest._impi = "1231231231@home.domain";
  orig_digest._nonce = "nonce";
  orig_digest._ha1 = "123123123";
  orig_digest._opaque = "opaque";
  orig_digest._realm = "home.domain";
  orig_digest._impu = "sip:1231231232@home.domain"; // This does not match the IMPI.
  _auth_store->set_digest(orig_digest._impi, orig_digest._nonce, &orig_digest, DUMMY_TRAIL_ID);

  // Read the digest back.  This simulates the processing just before the
  // authenticated request is checked.
  AuthStore::Digest* digest;
  _auth_store->get_digest(orig_digest._impi, orig_digest._nonce, digest, DUMMY_TRAIL_ID);

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

// This test checks the behaviour when the authenticator tries to update the
// nonce count in the auth store, and the set fails with DATA_CONTENTION. This
// simulates the case where the nonce has already been used to authenticate a
// request, and is now stale. The authenticator therefore rechallenges the
// request with the stale flag set.
TEST_F(HTTPDigestAuthenticateMockStoreTest, CheckIfMatches_NonceUpdateFails_RaceCondition)
{
  // Set up an existing digest to pass into `check_if_matches`.
  AuthStore::Digest *digest = new AuthStore::Digest();
  digest->_impi = "1231231231@home.domain";
  digest->_nonce = "nonce";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "home.domain";
  digest->_impu = "sip:1231231231@home.domain";

  // The authenticator will request a new digest from homestead. Prepare for
  // this.
  std::vector<std::string> test;
  test.push_back("digest_1");
  test.push_back("realm");
  _hc->set_result("/impi/1231231231%40home.domain/av?impu=sip%3A1231231231%40home.domain", test);

  // Set the _impu
  _auth_mod->set_members("sip:1231231231@home.domain", "GET", "1231231231@home.domain", 0);
  _response->set_members("1231231231","home.domain","nonce","org.projectclearwater.call-list/users/1231231231@home.domain/call-list.xml","qop","00001","cnonce","242c99c1e20618147c6a325c09720664","opaque");

  // The auth store is called twice:
  // - Once to update the nonce count on the existing digest (which fails with
  //   DATA_CONTENTION).
  // - Once to store the new digest from homestead (which succeeds).
  EXPECT_CALL(_mock_auth_store, set_digest(_, _, _, _))
    .WillOnce(Return(Store::DATA_CONTENTION))
    .WillOnce(Return(Store::OK));

  // Run through check if matches. This should rechallenge the request.
  std::string www_auth_header;
  long rc = _auth_mod->check_if_matches(digest, www_auth_header, _response);

  EXPECT_THAT(www_auth_header,
              MatchesRegex("Digest realm=\"home\\.domain\",qop=\"auth\",nonce=\".*\",opaque=\".*\",stale=TRUE"));
  ASSERT_EQ(rc, 401);

  delete digest; digest = NULL;
}
