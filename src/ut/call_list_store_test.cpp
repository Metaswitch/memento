/**
 * @file call_list_store_test.cpp Call list store unit tests
 *
 * Project Clearwater - IMS in the cloud.
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

#ifndef CALL_LIST_STORE_TEST_CPP_
#define CALL_LIST_STORE_TEST_CPP_

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "mock_cassandra_store.h"
#include "cass_test_utils.h"

#include "call_list_store.h"

using namespace CassTestUtils;

const SAS::TrailId FAKE_TRAIL = 0x123456;

// The class under test.
//
// We can't test the call list store directly as we need to supply a mock
// client, and therefore override the get_client() and relese_client()
// methods.
class TestCallListStore : public CallListStore::Store
{
public:
  MOCK_METHOD0(get_client, CassandraStore::ClientInterface*());
  MOCK_METHOD0(release_client, void());
};

class CallListStoreFixture : public ::testing::Test
{
public:
  CallListStoreFixture()
  {
    // The store always returns the mock client.
    EXPECT_CALL(_store, get_client()).WillRepeatedly(Return(&_client));
    EXPECT_CALL(_store, release_client()).WillRepeatedly(Return());

    _store.initialize();
    _store.configure("localhost", 1234);
    CassandraStore::ResultCode rc = _store.start();
    EXPECT_EQ(rc, CassandraStore::OK);
  }

  virtual ~CallListStoreFixture()
  {
    _store.stop();
    _store.wait_stopped();
  }

  TestCallListStore _store;
  MockCassandraClient _client;
};

//
// TESTS
//
TEST_F(CallListStoreFixture, WriteFragmentMainline)
{
  const std::string CALL_TIMESTAMP = "20140723150400";
  const std::string ID = "0123456789ABCDEF";
  const std::string CONTENT = "<xml>";
  const std::string EXPECT_COL_PREFIX = "call_20140723150400_0123456789ABCDEF_";

  CallListStore::CallFragment frag;
  frag.timestamp = CALL_TIMESTAMP;
  frag.id = ID;
  frag.contents = CONTENT;

  std::map<std::string, std::string> columns;

  // Test that the store can write begin records.
  columns.clear();
  columns[EXPECT_COL_PREFIX + "begin"] = "<xml>";
  frag.type = CallListStore::CallFragment::BEGIN;

  EXPECT_CALL(_client, batch_mutate(
                         MutationMap("call_lists", "kermit", columns, 1000, 3600),
                         _));

  CassandraStore::ResultCode rc =
    _store.write_call_fragment_sync("kermit", frag, 1000, 3600, FAKE_TRAIL);

  EXPECT_EQ(rc, CassandraStore::OK);

  // TODO Also check it can write end and rejected records.
}


TEST_F(CallListStoreFixture, GetFragmentsMainline)
{
  // Make a slice to return to the store.
  std::map<std::string, std::string> columns;
  columns["call_20140101130100_0000000000000000_begin"] = "<begin-record>";
  columns["call_20140101130100_0000000000000000_end"] = "<end-record>";
  columns["call_20140101130100_0000000000000001_rejected"] = "<rejected-record>";

  slice_t slice;
  make_slice(slice, columns);

  // The call fragments retrieved by the store.
  std::vector<CallListStore::CallFragment> fetched_fragments;

  // Expect the store to request a slice from cassandra, and return the one we
  // made earlier.
  EXPECT_CALL(_client, get_slice(_,
                                 "kermit",
                                 ColumnPathForTable("call_lists"),
                                 ColumnsWithPrefix("call_"),
                                 _))
   .WillOnce(SetArgReferee<0>(slice));

  // Now actually invoke the store.
  CassandraStore::ResultCode rc =
    _store.get_call_fragments_sync("kermit", fetched_fragments, FAKE_TRAIL);

  // Check that worked.
  EXPECT_EQ(rc, CassandraStore::OK);

  // We should have all 3 records back.
  EXPECT_EQ(fetched_fragments.size(), 3u);

  // Check the 3 records that came back.
  EXPECT_EQ(fetched_fragments[0].timestamp, "20140101130100");
  EXPECT_EQ(fetched_fragments[0].id, "0000000000000000");
  EXPECT_EQ(fetched_fragments[0].type, CallListStore::CallFragment::BEGIN);
  EXPECT_EQ(fetched_fragments[0].contents, "<begin-record>");

  EXPECT_EQ(fetched_fragments[1].timestamp, "20140101130100");
  EXPECT_EQ(fetched_fragments[1].id, "0000000000000000");
  EXPECT_EQ(fetched_fragments[1].type, CallListStore::CallFragment::END);
  EXPECT_EQ(fetched_fragments[1].contents, "<end-record>");

  EXPECT_EQ(fetched_fragments[2].timestamp, "20140101130100");
  EXPECT_EQ(fetched_fragments[2].id, "0000000000000001");
  EXPECT_EQ(fetched_fragments[2].type, CallListStore::CallFragment::REJECTED);
  EXPECT_EQ(fetched_fragments[2].contents, "<rejected-record>");
}


TEST_F(CallListStoreFixture, DeleteOldFragmentsMainline)
{
  const std::string CALL_TIMESTAMP = "20140101130100";

  EXPECT_CALL(_client, batch_mutate(DeletionRange("kermit",
                                                  "call_lists",
                                                  "call_",
                                                  "call_" + CALL_TIMESTAMP,
                                                  1000),
                                    _));

  CassandraStore::ResultCode rc =
    _store.delete_old_call_fragments_sync("kermit", CALL_TIMESTAMP, 1000, FAKE_TRAIL);

  EXPECT_EQ(rc, CassandraStore::OK);
}

#endif

