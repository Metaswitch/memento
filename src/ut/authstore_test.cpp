/**
 * @file authstore_test.cpp
 *
 * Copyright (C) Metaswitch Networks
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
#include "localstore.h"
#include "authstore.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "mock_store.h"

using namespace std;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

// These tests use "typed tests" to run the same tests over different
// (de)serializers. For more information see:
// https://code.google.com/p/googletest/wiki/AdvancedGuide#Typed_Tests

/// The types of (de)serializer that we want to test.
typedef ::testing::Types<
  AuthStore::BinarySerializerDeserializer,
  AuthStore::JsonSerializerDeserializer
> SerializerDeserializerTypes;

/// Fixture for BasicAuthStoreTest.  This uses a single AuthStore,
/// configured to use exactly one (de)serializer.
///
/// The fixture is a template, parameterized over the different types of
/// (de)serializer.
template<class T>
class BasicAuthStoreTest : public ::testing::Test
{
  BasicAuthStoreTest()
  {
    _local_data_store = new LocalStore();
    AuthStore::SerializerDeserializer* serializer = new T();
    std::vector<AuthStore::SerializerDeserializer*> deserializers = {
      new T(),
    };

    _auth_store = new AuthStore(_local_data_store,
                                serializer,
                                deserializers,
                                300);
  }

  virtual ~BasicAuthStoreTest()
  {
    delete _local_data_store; _local_data_store = NULL;
    delete _auth_store; _auth_store = NULL;
    cwtest_reset_time();
  }

  LocalStore* _local_data_store;
  AuthStore* _auth_store;
};

// BasicSessionStoreTest is parameterized over these types.
TYPED_TEST_CASE(BasicAuthStoreTest, SerializerDeserializerTypes);


TYPED_TEST(BasicAuthStoreTest, SimpleWriteRead)
{
  // Write a digest to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";

  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "6505551234@cw-ngv.com";
  digest->_nonce = "9876543210";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "cw-ngv.com";
  digest->_nonce_count = 3;
  digest->_impu = "sip:" + impi;

  this->_auth_store->set_digest(impi, nonce, digest, 0);

  // Retrieve the digest from the store and check it against
  // the initial digest
  AuthStore::Digest* digest2;
  this->_auth_store->get_digest(impi, nonce, digest2, 0);

  ASSERT_EQ(digest->_impi, digest2->_impi);
  ASSERT_EQ(digest->_nonce, digest2->_nonce);
  ASSERT_EQ(digest->_ha1, digest2->_ha1);
  ASSERT_EQ(digest->_realm, digest2->_realm);
  ASSERT_EQ(digest->_opaque, digest2->_opaque);
  ASSERT_EQ(digest->_impu, digest2->_impu);
  ASSERT_EQ(digest->_nonce_count, digest2->_nonce_count);

  delete digest; digest = NULL;
  delete digest2; digest2 = NULL;
}

TYPED_TEST(BasicAuthStoreTest, ReadExpired)
{
  cwtest_completely_control_time();

  // Write a digest to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";

  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "6505551234@cw-ngv.com";
  digest->_nonce = "9876543210";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "cw-ngv.com";

  this->_auth_store->set_digest(impi, nonce, digest, 0);

  // Advance the time by 299 seconds and read the record.
  cwtest_advance_time_ms(299000);
  AuthStore::Digest* digest2;
  this->_auth_store->get_digest(impi, nonce, digest2, 0);

  ASSERT_EQ(digest->_ha1, digest2->_ha1);

  // Advance the time another 2 seconds to expire the record.
  cwtest_advance_time_ms(2000);
  AuthStore::Digest* digest3;
  this->_auth_store->get_digest(impi, nonce, digest3, 0);

  ASSERT_EQ(NULL, digest3);

  delete digest; digest = NULL;
  delete digest2; digest2 = NULL;
  delete digest3; digest3 = NULL;
}


/// Fixture for MultiFormatAuthStoreTest.  This uses a two AuthStores:
/// 1). One that reads and writes only one format.
/// 2). One that can read all formats.
///
/// The fixture is a template, parameterized over the different types of
/// (de)serializer.
template<class T>
class MultiFormatAuthStoreTest : public ::testing::Test
{
  MultiFormatAuthStoreTest()
  {
    _local_data_store = new LocalStore();

    {
      AuthStore::SerializerDeserializer* serializer = new T();
      std::vector<AuthStore::SerializerDeserializer*> deserializers = {
        new T(),
      };

      _single_store = new AuthStore(_local_data_store,
                                    serializer,
                                    deserializers,
                                    300);
    }

    {
      AuthStore::SerializerDeserializer* serializer =
        new AuthStore::JsonSerializerDeserializer();
      std::vector<AuthStore::SerializerDeserializer*> deserializers = {
        new AuthStore::JsonSerializerDeserializer(),
        new AuthStore::BinarySerializerDeserializer(),
      };

      _multi_store = new AuthStore(_local_data_store,
                                   serializer,
                                   deserializers,
                                   300);
    }
  }

  virtual ~MultiFormatAuthStoreTest()
  {
    delete _local_data_store; _local_data_store = NULL;
    delete _single_store; _single_store = NULL;
    delete _multi_store; _multi_store = NULL;
    cwtest_reset_time();
  }

  LocalStore* _local_data_store;
  AuthStore* _single_store;
  AuthStore* _multi_store;
};

// MultiFormatAuthStoreTest is parameterized over these types.
TYPED_TEST_CASE(MultiFormatAuthStoreTest, SerializerDeserializerTypes);


TYPED_TEST(MultiFormatAuthStoreTest, CanReadAllFormats)
{
  // Write a digest to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";

  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "6505551234@cw-ngv.com";
  digest->_nonce = "9876543210";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "cw-ngv.com";
  digest->_nonce_count = 3;
  digest->_impu = "sip:" + impi;

  this->_single_store->set_digest(impi, nonce, digest, 0);

  // Retrieve the digest from the store and check it against
  // the initial digest
  AuthStore::Digest* digest2;
  this->_multi_store->get_digest(impi, nonce, digest2, 0);

  ASSERT_EQ(digest->_impi, digest2->_impi);
  ASSERT_EQ(digest->_nonce, digest2->_nonce);
  ASSERT_EQ(digest->_ha1, digest2->_ha1);
  ASSERT_EQ(digest->_realm, digest2->_realm);
  ASSERT_EQ(digest->_opaque, digest2->_opaque);
  ASSERT_EQ(digest->_impu, digest2->_impu);
  ASSERT_EQ(digest->_nonce_count, digest2->_nonce_count);

  delete digest; digest = NULL;
  delete digest2; digest2 = NULL;
}


class CorruptDataAuthStoreTest : public ::testing::Test
{
  CorruptDataAuthStoreTest()
  {
    _mock_store = new MockStore();

    AuthStore::SerializerDeserializer* serializer =
      new AuthStore::JsonSerializerDeserializer();
    std::vector<AuthStore::SerializerDeserializer*> deserializers = {
      new AuthStore::JsonSerializerDeserializer(),
      new AuthStore::BinarySerializerDeserializer(),
    };

    _auth_store = new AuthStore(_mock_store,
                                serializer,
                                deserializers,
                                300);
  }

  virtual ~CorruptDataAuthStoreTest()
  {
    delete _mock_store; _mock_store = NULL;
    delete _auth_store; _auth_store = NULL;
    cwtest_reset_time();
  }

  MockStore* _mock_store;
  AuthStore* _auth_store;
};


TEST_F(CorruptDataAuthStoreTest, BadlyFormedJson)
{
  AuthStore::Digest* digest;
  Store::Status rc;

  std::string impi = "kermit@cw-ngv.com";
  std::string nonce = "987654321";

  EXPECT_CALL(*_mock_store, get_data(_, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<2>(std::string("{ \"ha1\": \"12345\", "
                                                   "\"realm\": \"cw-ngv.com\", ")),
                    SetArgReferee<3>(1), // CAS
                    Return(Store::OK)));

  rc = _auth_store->get_digest(impi, nonce, digest, 0);
  ASSERT_TRUE(digest == NULL);
  EXPECT_EQ(Store::NOT_FOUND, rc);
}


TEST_F(CorruptDataAuthStoreTest, SemanticallyInvalidJson)
{
  AuthStore::Digest* digest;
  Store::Status rc;

  std::string impi = "kermit@cw-ngv.com";
  std::string nonce = "987654321";

  // JSON is invalid because "ha1" and "realm" should be in a "digest" object.
  EXPECT_CALL(*_mock_store, get_data(_, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<2>(std::string("{ \"ha1\": \"12345\", "
                                                   "\"realm\": \"cw-ngv.com\", "
                                                   "\"opaque\": \"blahblahblah\", "
                                                   "\"impu\": \"kermit@cw-ngv.com\", "
                                                   "\"nc\": 1}")),
                    SetArgReferee<3>(1), // CAS
                    Return(Store::OK)));

  rc = _auth_store->get_digest(impi, nonce, digest, 0);
  ASSERT_TRUE(digest == NULL);
  EXPECT_EQ(Store::NOT_FOUND, rc);
}
