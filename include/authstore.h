/**
 * @file avstore.h  Definition of class for storing Authentication Vectors
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

#ifndef AUTHSTORE_H_
#define AUTHSTORE_H_

#include "store.h"

class AuthStore
{
public:
  /// @class AuthStore::Digest
  ///
  /// Represents a Digest
  class Digest
  {
  public:
    /// HA1 - supplied on client request
    std::string _ha1;

    /// opaque - supplied on client request or generated
    /// from the timestamp
    std::string _opaque;

    /// nonce - supplied on client request or generated
    /// from the timestamp
    std::string _nonce;

    /// impi - Private ID
    std::string _impi;

    /// realm - supplied on client request or defaults
    /// to the home domain
    std::string _realm;

    /// nonce_count - supplied on client request and incremented
    /// when the digest is examined
    uint32_t _nonce_count;

    /// impu - Public ID
    std::string _impu;

    /// Default Constructor.
    Digest();

    /// Destructor.
    ~Digest();

  private:
    /// Memcached CAS value.
    uint64_t _cas;

    // The auth store is a friend so it can read the digest's CAS value.
    friend class AuthStore;
  };

  /// Constructor.
  /// @param data_store    A pointer to the underlying data store.
  /// @param expiry        Expiry time of entries
  AuthStore(Store* data_store,
            int expiry);

  /// Destructor.
  ~AuthStore();

  /// set_digest.
  ///
  /// @param impi   A reference to the private user identity.
  /// @param nonce  A reference to the nonce.
  /// @param digest A pointer to a Digest object to store
  ///
  /// @return       The status code returned by the store.
  Store::Status set_digest(const std::string& impi,
                           const std::string& nonce,
                           const Digest*,
                           SAS::TrailId);

  /// get_digest.
  ///
  /// @param impi   A reference to the private user identity.
  /// @param nonce  A reference to the nonce.
  /// @param digest A Digest object to populate with the retrieved Digest. Caller is
  ///               responsible for deleting
  ///
  /// @return       The status code returned by the store.
  Store::Status get_digest(const std::string& impi,
                           const std::string& nonce,
                           Digest*&,
                           SAS::TrailId);

private:
  std::string serialize_digest(const Digest* digest);
  Digest* deserialize_digest(const std::string& digest_s);

  /// A pointer to the underlying data store.
  Store* _data_store;

  /// Time to expire Digest record (controlled by configuration)
  int _expiry;
};

#endif
