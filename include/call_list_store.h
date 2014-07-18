/**
 * @file call_list_store.h Call list cassandra store.
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

#ifndef CALL_LIST_STORE_H__
#define CALL_LIST_STORE_H__

#include "cassandra_store.h"

namespace CallListStore
{

/// Structure representing a call record in the store.
struct CallRecord
{
  enum Type
  {
    BEGIN,
    END,
    REJECTED
  };

  tm timestamp;
  std::string id;
  Type type;
  std::string contents;
};


/// Operation that adds a new call record to the store.
class WriteCallRecord : public CassandraStore::Operation
{
  /// Constructor.
  ///
  /// @param impu     - The IMPU to write a record for.
  /// @param record   - The record object to write.
  /// @param ttl      - The TTL (in seconds) for the column.
  WriteCallRecord(const std::string& impu,
                  const CallRecord& record,
                  const int32_t ttl = 0);
  virtual ~WriteCallRecord();

  bool perform();

protected:
  const std::string _impu;
  const CallRecord _record;
  const int32_t _ttl;
};


/// Operation that gets call records for a particular IMPU.
class GetCallRecords : public CassandraStore::Operation
{
  /// Constructor.
  /// @param impu     - The IMPU whose call records to retrieve.
  GetCallRecords(std::string& impu);

  /// Virtual destructor.
  virtual ~GetCallRecords();

  bool perform();

  /// Get the fetched call records.  These are guaranteed to be ordered first
  /// by timestamp, then by id, then by type.
  ///
  /// @return    - A *reference* to a vector of call records.
  std::vector<CallRecord>& get_call_records();

protected:
  const std::string _impu;

  std::vector<CallRecord> _records;
};


/// Operation that deletes all records for an IMPU that occurred before a given
/// timestamp.
class DeleteOldCallRecords : public CassandraStore::Operation
{
  /// Constructor
  ///
  /// @param impu       - The IMPU whose old records to delete.
  /// @param threshold  - The threshold time. Records with a timestamp that is
  ///                     earlier than this time will be deleted (but records
  ///                     with an equal timestamp will not).
  DeleteOldCallRecords(std::string& impu, tm& age);

  /// Virtual destructor.
  virtual ~DeleteOldCallRecords();

  bool perform();

protected:
  const std::string _impu;
  const tm _age;
};


/// Call List store class.
///
/// This is a thin layer on top of a CassandraStore that provides some
/// additional utility methods.
class Store : public CassandraStore::Store
{
public:

  /// Constructor
  Store();

  /// Virtual destructor.
  virtual ~Store();

  //
  // Methods to create new operation objects.
  //
  // These should be used in preference to creating operations directly (using
  // 'new') as this makes the store easier to mock out in UT.
  //
  virtual WriteCallRecord*
    new_write_call_record_op(const std::string& impu,
                             const CallRecord& record,
                             const int32_t ttl = 0);
  virtual GetCallRecords*
    new_get_call_records_op(const std::string& impu);
  virtual DeleteOldCallRecords*
    new_delete_old_call_records_op(const std::string& impu,
                                   const tm& age);

  //
  // Utility methods to perform synchronous operations more easily.
  //
  virtual CassandraStore::ResultCode
    write_call_record_sync(const std::string& impu,
                           const CallRecord& record,
                           const int32_t ttl = 0);
  virtual CassandraStore::ResultCode
    get_call_records_sync(const std::string& impu,
                          std::vector<CallRecord>& records);
  virtual CassandraStore::ResultCode
    delete_old_call_records_sync(const std::string& impu,
                                 const tm& threshold);
};

} // namespace CallListStore

#endif
