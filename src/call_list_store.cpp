/**
 * @file call_list_store.cpp Memento call list store implementation.
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

#include "call_list_store.h"

const static std::string KEYSPACE = "memento";
const static std::string COLUMN_FAMILY = "call_lists";

const static std::string STR_BEGIN = "begin";
const static std::string STR_END = "end";
const static std::string STR_REJECTED = "rejected";

const static std::string CALL_COLUMN_PREFIX = "call";

namespace CallListStore
{

std::string fragment_type_to_string(CallFragment::Type type)
{
  switch(type)
  {
    case CallFragment::BEGIN:
      return STR_BEGIN;

    case CallFragment::END:
      return STR_END;

    case CallFragment::REJECTED:
      return STR_REJECTED;

    default:
      // LCOV_START - We should never reach this code.  The function must be
      // passed a value in the enumeration, and we have already handled all of
      // them.
      LOG_ERROR("Unexpected call fragment type %d", (int)type);
      assert(!"Unexpected call fragment type");
      return STR_BEGIN;
      // LCOV_STOP
  }
}

CallFragment::Type fragment_type_from_string(const std::string& fragment_str)
{
  if (fragment_str == STR_BEGIN)
  {
    return CallFragment::BEGIN;
  }
  else if (fragment_str == STR_END)
  {
    return CallFragment::END;
  }
  else if (fragment_str == STR_REJECTED)
  {
    return CallFragment::REJECTED;
  }
  else
  {
    throw std::string("Unrecognized fragment type: ") + fragment_str;
  }
}

Store::Store() : CassandraStore::Store(KEYSPACE) {}

Store::~Store() {}

//
// Operation definitions.
//

WriteCallFragment::WriteCallFragment(const std::string& impu,
                                     const CallFragment& fragment,
                                     const int32_t ttl) :
  _impu(impu), _fragment(fragment), _ttl(ttl)
{}

WriteCallFragment::~WriteCallFragment()
{}

bool WriteCallFragment::perform(CassandraStore::ClientInterface* client,
                                SAS::TrailId trail)
{
  std::string column_name;
  column_name.append(CALL_COLUMN_PREFIX).append("_")
             .append(_fragment.timestamp).append("_")
             .append(_fragment.id).append("_")
             .append(fragment_type_to_string(_fragment.type));

  std::map<std::string, std::string> columns;
  columns[column_name] = _fragment.contents;

  std::vector<std::string> keys;
  keys.push_back(_impu);

  put_columns(client,
              COLUMN_FAMILY,
              keys,
              columns,
              CassandraStore::Store::generate_timestamp(),
              _ttl);

  return true;
}

WriteCallFragment*
  Store::new_write_call_fragment_op(const std::string& impu,
                                    const CallFragment& fragment,
                                    const int32_t ttl)
{
  return new WriteCallFragment(impu, fragment, ttl);
}









GetCallFragments*
  Store::new_get_call_fragments_op(const std::string& impu)
{
  return NULL;
}


DeleteOldCallFragments*
Store::new_delete_old_call_fragments_op(const std::string& impu,
                                        const std::string& timestamp)
{
  return NULL;
}


CassandraStore::ResultCode
Store::write_call_fragment_sync(const std::string& impu,
                                const CallFragment& fragment,
                                const int32_t ttl,
                                SAS::TrailId trail)
{
  CassandraStore::ResultCode result = CassandraStore::OK;
  WriteCallFragment write_call_fragment(impu, fragment, ttl);

  if (!do_sync(&write_call_fragment, trail))
  {
    result = write_call_fragment.get_result_code();
    std::string error_text = write_call_fragment.get_error_text();
    LOG_WARNING("Failed to write call list fragment for IMPU %s because '%s' (RC = %d)",
                impu.c_str(), error_text.c_str(), result);
  }

  return result;
}


CassandraStore::ResultCode
Store::get_call_fragments_sync(const std::string& impu,
                               std::vector<CallFragment>& fragments,
                               SAS::TrailId trail)
{
  return CassandraStore::OK;
}


CassandraStore::ResultCode
Store::delete_old_call_fragments_sync(const std::string& impu,
                                      const std::string& timestamp,
                                      SAS::TrailId trail)
{
  return CassandraStore::OK;
}

} // namespace CallListStore
