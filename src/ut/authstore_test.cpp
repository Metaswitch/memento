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
#include "localstore.h"
#include "authstore.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Fixture for AuthStoreTest.
class AuthStoreTest : public ::testing::Test
{
  AuthStoreTest()
  {
  }

  virtual ~AuthStoreTest()
  {
  }
};


TEST_F(AuthStoreTest, SimpleWriteRead)
{
  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 300);

  // Write a digest to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";

  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "6505551234@cw-ngv.com";
  digest->_nonce = "9876543210";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "cw-ngv.com";

  auth_store->set_digest(impi, nonce, digest, 0);

  // Retrieve the digest from the store and check it against
  // the initial digest
  AuthStore::Digest* digest2;
  auth_store->get_digest(impi, nonce, digest2, 0);

  ASSERT_EQ(digest->_ha1, digest2->_ha1);

  delete digest; digest = NULL;
  delete digest2; digest2 = NULL;
  delete auth_store; auth_store = NULL;
  delete local_data_store; local_data_store = NULL;
}

TEST_F(AuthStoreTest, ReadExpired)
{
  cwtest_completely_control_time();

  LocalStore* local_data_store = new LocalStore();
  AuthStore* auth_store = new AuthStore(local_data_store, 30);

  // Write a digest to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";

  AuthStore::Digest* digest = new AuthStore::Digest();
  digest->_impi = "6505551234@cw-ngv.com";
  digest->_nonce = "9876543210";
  digest->_ha1 = "123123123";
  digest->_opaque = "opaque";
  digest->_realm = "cw-ngv.com";

  auth_store->set_digest(impi, nonce, digest, 0);

  // Advance the time by 29 seconds and read the record.
  cwtest_advance_time_ms(29000);
  AuthStore::Digest* digest2;
  auth_store->get_digest(impi, nonce, digest2, 0);

  ASSERT_EQ(digest->_ha1, digest2->_ha1);

  // Advance the time another 2 seconds to expire the record.
  cwtest_advance_time_ms(2000);
  AuthStore::Digest* digest3;
  auth_store->get_digest(impi, nonce, digest3, 0);

  ASSERT_EQ(NULL, digest3);

  delete digest; digest = NULL;
  delete digest2; digest2 = NULL;
  delete digest3; digest3 = NULL;
  delete auth_store; auth_store = NULL;
  delete local_data_store; local_data_store = NULL;
}
