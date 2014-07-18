/**
 * @file mock_call_list_store.h Mock call list store object.
 *
 * Project Clearwater - IMS in the cloud.
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#ifndef MOCK_CALL_LIST_STORE_H__
#define MOCK_CALL_LIST_STORE_H__

#include "call_list_store.h"
#include "mock_cassandra_store.h"

class MockCallListStore : public MockCassandraStore<CallListStore::Store>
{
public:
  virtual ~MockCallListStore() {};

  MOCK_METHOD3(new_write_call_record_op,
               CallListStore::WriteCallRecord*(const std::string& impu,
                                               const CallListStore::CallRecord& record,
                                               const int32_t ttl));

  MOCK_METHOD1(new_get_call_records_op,
               CallListStore::GetCallRecords*(const std::string& impu));

  MOCK_METHOD2(new_delete_old_call_records_op,
               CallListStore::DeleteOldCallRecords*(std::string& impu, tm& age));

  MOCK_METHOD3(write_call_record_sync,
               CassandraStore::ResultCode(const std::string& impu,
                                          const CallListStore::CallRecord& record,
                                          const int32_t ttl));
  MOCK_METHOD2(get_call_records_sync,
               CassandraStore::ResultCode(const std::string& impu,
                                          std::vector<CallListStore::CallRecord>& records));

  MOCK_METHOD2(delete_old_call_records_sync,
               CassandraStore::ResultCode(const std::string& impu,
                                          const tm& threshold));
};

#endif

