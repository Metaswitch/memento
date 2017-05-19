/**
 * @file authstore.h  Definition of class for storing Authentication Vectors
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

  /// Interface used by the AuthStore to serialize digests from C++ objects to
  /// the format used in the store, and deserialize them.
  ///
  /// This interface allows multiple (de)serializers to be defined and for the
  /// AuthStore to use them in a pluggable fashion.
  class SerializerDeserializer
  {
  public:
    /// Virtual destructor.
    virtual ~SerializerDeserializer() {};

    /// Serialize a Digest object to the format used in the store.
    ///
    /// @param digest - The digest to serialize.
    /// @return       - The serialized form.
    virtual std::string serialize_digest(const Digest* digest) = 0;

    /// Deserialize some data from the store to a Digest object.
    ///
    /// @param digest_s - The data to deserialize.
    /// @return         - A digest object, or NULL if the data could not be
    ///                   deserialized (e.g. because it is corrupt).
    virtual Digest* deserialize_digest(const std::string& digest_s) = 0;

    /// @return - The name of this (de)serializer.
    virtual std::string name() = 0;
  };

  /// A (de)serializer for the (deprecated) custom binary format.
  class BinarySerializerDeserializer : public SerializerDeserializer
  {
  public:
    ~BinarySerializerDeserializer() {};

    std::string serialize_digest(const Digest* digest);
    Digest* deserialize_digest(const std::string& digest_s);
    std::string name();
  };

  /// A (de)serializer for the JSON format.
  class JsonSerializerDeserializer : public SerializerDeserializer
  {
  public:
    ~JsonSerializerDeserializer() {};

    std::string serialize_digest(const Digest* digest);
    Digest* deserialize_digest(const std::string& digest_s);
    std::string name();
  };

  /// Constructor.
  ///
  /// @param data_store    A pointer to the underlying data store.
  /// @param serializer    The serializer to use when writing digests.
  ///                      The AuthStore takes ownership of it.
  /// @param deserializer  A vector of deserializers to try when reading
  ///                      digests. The order is important - each deserializer
  ///                      is tried in turn until one successfully parses the
  ///                      record.  The AuthStore takes ownership of the
  ///                      deserializers in the vector.
  /// @param expiry        Expiry time of entries
  AuthStore(Store* data_store,
            SerializerDeserializer*& serializer,
            std::vector<SerializerDeserializer*>& _deserializers,
            int expiry);

  /// Alternative constructor that creates an AuthStore with just the default
  /// (de)serializer.
  ///
  /// @param data_store    A pointer to the underlying data store.
  /// @param expiry        Expiry time of entries
  AuthStore(Store* data_store,
            int expiry);

  /// Destructor.
  virtual ~AuthStore();

  /// set_digest.
  ///
  /// @param impi   A reference to the private user identity.
  /// @param nonce  A reference to the nonce.
  /// @param digest A pointer to a Digest object to store
  ///
  /// @return       The status code returned by the store.
  virtual Store::Status set_digest(const std::string& impi,
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
  virtual Store::Status get_digest(const std::string& impi,
                                   const std::string& nonce,
                                   Digest*&,
                                   SAS::TrailId);

private:
  std::string serialize_digest(const Digest* digest);
  Digest* deserialize_digest(const std::string& digest_s);

  /// A pointer to the underlying data store.
  Store* _data_store;

  /// Serializer to use when writing records, and a vector of deserializers to
  /// try when reading them.
  SerializerDeserializer* _serializer;
  std::vector<SerializerDeserializer*> _deserializers;

  /// Time to expire Digest record (controlled by configuration)
  int _expiry;
};

#endif
