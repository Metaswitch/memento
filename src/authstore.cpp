/**
 * @file avstore.cpp Implementation of store for Authentication Vectors
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

#include <iostream>
#include <sstream>
#include <fstream>

#include "store.h"
#include "authstore.h"
#include "log.h"
#include "sas.h"
#include "mementosasevent.h"

AuthStore::AuthStore(Store* data_store, int expiry) :
  _data_store(data_store),
  _expiry(expiry)
{
}

AuthStore::~AuthStore()
{
}

Store::Status AuthStore::set_digest(const std::string& impi,
                                    const std::string& nonce,
                                    const AuthStore::Digest* digest,
                                    SAS::TrailId trail)
{
  std::string key = impi + '\\' + nonce;
  std::string data = serialize_digest(digest);

  LOG_DEBUG("Set digest for %s\n%s", key.c_str(), data.c_str());

  Store::Status status = _data_store->set_data("AuthStore",
                                               key,
                                               data,
                                               digest->_cas,
                                               _expiry,
                                               trail);

  if (status != Store::Status::OK)
  {
    // LCOV_EXCL_START - Store used in UTs doesn't fail
    LOG_ERROR("Failed to write digest for key %s", key.c_str());

    SAS::Event event(trail, SASEvent::AUTHSTORE_SET_FAILURE, 0);
    event.add_var_param(key);
    event.add_var_param(data);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }
  else
  {
    SAS::Event event(trail, SASEvent::AUTHSTORE_SET_SUCCESS, 0);
    event.add_var_param(key);
    event.add_var_param(data);
    SAS::report_event(event);
  }

  return status;
}


Store::Status AuthStore::get_digest(const std::string& impi,
                                    const std::string& nonce,
                                    AuthStore::Digest*& digest,
                                    SAS::TrailId trail)
{
  std::string key = impi + '\\' + nonce;
  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data("AuthStore", key, data, cas, trail);

  LOG_DEBUG("Get digest for %s", key.c_str());

  if (status != Store::Status::OK)
  {
    LOG_DEBUG("Failed to retrieve digest for %s", key.c_str());
    SAS::Event event(trail, SASEvent::AUTHSTORE_GET_FAILURE, 0);
    event.add_var_param(key);
    SAS::report_event(event);

    digest = NULL;
  }
  else
  {
    LOG_DEBUG("Retrieved Digest for %s\n%s", key.c_str(), data.c_str());

    SAS::Event event(trail, SASEvent::AUTHSTORE_GET_SUCCESS, 0);
    event.add_var_param(key);
    event.add_var_param(data);
    SAS::report_event(event);

    digest = deserialize_digest(data);
    digest->_cas = cas;
  }

  return status;
}

AuthStore::Digest::Digest() :
  _ha1(""),
  _opaque(""),
  _nonce(""),
  _impi(""),
  _realm(""),
  _nonce_count(1),
  _impu(""),
  _cas(0)
{
}

AuthStore::Digest::~Digest()
{
}

AuthStore::Digest* AuthStore::deserialize_digest(const std::string& digest_s)
{
  std::istringstream iss(digest_s, std::istringstream::in|std::istringstream::binary);
  Digest* digest = new Digest();

  getline(iss, digest->_ha1, '\0');
  getline(iss, digest->_opaque, '\0');
  getline(iss, digest->_nonce, '\0');
  getline(iss, digest->_impi, '\0');
  getline(iss, digest->_realm, '\0');
  iss.read((char *)&digest->_nonce_count, sizeof(uint32_t));
  getline(iss, digest->_impu, '\0');

  return digest;
}

std::string AuthStore::serialize_digest(const AuthStore::Digest* digest_d)
{
  std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);
  oss << digest_d->_ha1 << '\0';
  oss << digest_d->_opaque << '\0';
  oss << digest_d->_nonce << '\0';
  oss << digest_d->_impi << '\0';
  oss << digest_d->_realm << '\0';
  oss.write((const char *)&digest_d->_nonce_count, sizeof(int));
  oss << digest_d->_impu << '\0';

  return oss.str();
}
