/**
 * @file authstore.cpp Implementation of store for Authentication Vectors
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <iostream>
#include <sstream>
#include <fstream>

#include "store.h"
#include "authstore.h"
#include "log.h"
#include "sas.h"
#include "mementosasevent.h"
#include "json_parse_utils.h"

AuthStore::AuthStore(Store* data_store, int expiry) :
  _data_store(data_store),
  _expiry(expiry)
{
  _serializer = new JsonSerializerDeserializer();
  _deserializers.push_back(new JsonSerializerDeserializer());
}

AuthStore::AuthStore(Store* data_store,
                     SerializerDeserializer*& serializer,
                     std::vector<SerializerDeserializer*>& deserializers,
                     int expiry) :
  _data_store(data_store),
  _serializer(serializer),
  _deserializers(deserializers),
  _expiry(expiry)
{
  // Take ownership of the (de)serializers.
  serializer = NULL;
  deserializers.clear();
}

AuthStore::~AuthStore()
{
  delete _serializer; _serializer = NULL;

  for (std::vector<SerializerDeserializer*>::iterator it = _deserializers.begin();
       it != _deserializers.end();
       ++it)
  {
    delete *it; *it = NULL;
  }
}

Store::Status AuthStore::set_digest(const std::string& impi,
                                    const std::string& nonce,
                                    const AuthStore::Digest* digest,
                                    SAS::TrailId trail)
{
  std::string key = impi + '\\' + nonce;
  std::string data = serialize_digest(digest);

  TRC_DEBUG("Set digest for %s\n%s", key.c_str(), data.c_str());

  Store::Status status = _data_store->set_data("AuthStore",
                                               key,
                                               data,
                                               digest->_cas,
                                               _expiry,
                                               trail);

  if (status != Store::Status::OK)
  {
    // LCOV_EXCL_START - Store used in UTs doesn't fail
    TRC_ERROR("Failed to write digest for key %s", key.c_str());

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

  TRC_DEBUG("Get digest for %s", key.c_str());

  if (status != Store::Status::OK)
  {
    TRC_DEBUG("Failed to retrieve digest for %s", key.c_str());
    SAS::Event event(trail, SASEvent::AUTHSTORE_GET_FAILURE, 0);
    event.add_var_param(key);
    SAS::report_event(event);

    digest = NULL;
  }
  else
  {
    TRC_DEBUG("Retrieved Digest for %s\n%s", key.c_str(), data.c_str());
    digest = deserialize_digest(data);

    if (digest != NULL)
    {
      digest->_cas = cas;
      digest->_impi = impi;
      digest->_nonce = nonce;

      SAS::Event event(trail, SASEvent::AUTHSTORE_GET_SUCCESS, 0);
      event.add_var_param(key);
      event.add_var_param(data);
      SAS::report_event(event);
    }
    else
    {
      TRC_INFO("Failed to deserialize record");
      SAS::Event event(trail, SASEvent::AUTHSTORE_DESERIALIZATION_FAILURE, 0);
      event.add_var_param(key);
      event.add_var_param(data);
      SAS::report_event(event);

      // Handle as if the digest was not found.
      status = Store::NOT_FOUND;
    }
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
  Digest* digest = NULL;

  for (std::vector<SerializerDeserializer*>::const_iterator it = _deserializers.begin();
       it != _deserializers.end();
       ++it)
  {
    SerializerDeserializer* deserializer = *it;
    TRC_DEBUG("Try '%s' deserializer", deserializer->name().c_str());

    digest = deserializer->deserialize_digest(digest_s);

    if (digest != NULL)
    {
      TRC_DEBUG("Deserialization successful");
      break;
    }
    else
    {
      TRC_DEBUG("Deserialization failed");
    }
  }

  return digest;
}

std::string AuthStore::serialize_digest(const AuthStore::Digest* digest)
{
  return _serializer->serialize_digest(digest);
}

//
// Definition of the binary (de)serializer.
//

std::string AuthStore::BinarySerializerDeserializer::
  serialize_digest(const Digest* digest)
{
  std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);
  oss << digest->_ha1 << '\0';
  oss << digest->_opaque << '\0';
  oss << digest->_nonce << '\0';
  oss << digest->_impi << '\0';
  oss << digest->_realm << '\0';
  oss.write((const char *)&digest->_nonce_count, sizeof(int));
  oss << digest->_impu << '\0';

  return oss.str();
}

AuthStore::Digest* AuthStore::BinarySerializerDeserializer::
  deserialize_digest(const std::string& digest_s)
{
  // Helper macro that bails out if we unexpectedly hit the end of the input
  // stream.
#define ASSERT_NOT_EOF(STREAM)                                                 \
if ((STREAM).eof())                                                            \
{                                                                              \
  TRC_INFO("Failed to deserialize binary document (hit EOF at %s:%d)",         \
           __FILE__, __LINE__);                                                \
  delete digest; digest = NULL;                                                \
  return NULL;                                                                 \
}

  std::istringstream iss(digest_s, std::istringstream::in|std::istringstream::binary);
  Digest* digest = new Digest();

  getline(iss, digest->_ha1, '\0');
  ASSERT_NOT_EOF(iss);
  getline(iss, digest->_opaque, '\0');
  ASSERT_NOT_EOF(iss);
  getline(iss, digest->_nonce, '\0');
  ASSERT_NOT_EOF(iss);
  getline(iss, digest->_impi, '\0');
  ASSERT_NOT_EOF(iss);
  getline(iss, digest->_realm, '\0');
  ASSERT_NOT_EOF(iss);
  iss.read((char *)&digest->_nonce_count, sizeof(uint32_t));
  ASSERT_NOT_EOF(iss);
  getline(iss, digest->_impu, '\0');
  // Could legitimately be at the end of the stream now.

  return digest;
}

std::string AuthStore::BinarySerializerDeserializer::name()
{
  return "binary";
}


//
// Definition of the JSON (de)serializer.
//

static const char* const JSON_DIGEST = "digest";
static const char* const JSON_REALM = "realm";
static const char* const JSON_QOP = "qop";
static const char* const JSON_AUTH = "auth";
static const char* const JSON_HA1 = "ha1";
static const char* const JSON_OPAQUE = "opaque";
static const char* const JSON_IMPU = "impu";
static const char* const JSON_NC = "nc";

std::string AuthStore::JsonSerializerDeserializer::
  serialize_digest(const Digest* digest)
{
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

  writer.StartObject();
  {
    writer.String(JSON_DIGEST);
    writer.StartObject();
    {
      writer.String(JSON_REALM); writer.String(digest->_realm.c_str());
      writer.String(JSON_QOP); writer.String(JSON_AUTH);
      writer.String(JSON_HA1); writer.String(digest->_ha1.c_str());
    }
    writer.EndObject();

    writer.String(JSON_OPAQUE); writer.String(digest->_opaque.c_str());
    writer.String(JSON_IMPU); writer.String(digest->_impu.c_str());
    writer.String(JSON_NC); writer.Int(digest->_nonce_count);
  }
  writer.EndObject();

  return sb.GetString();
}

AuthStore::Digest* AuthStore::JsonSerializerDeserializer::
  deserialize_digest(const std::string& digest_s)
{
  TRC_DEBUG("Deserialize JSON document: %s", digest_s.c_str());

  rapidjson::Document doc;
  doc.Parse<0>(digest_s.c_str());

  if (doc.HasParseError())
  {
    TRC_DEBUG("Failed to parse document");
    return NULL;
  }

  Digest* digest = new Digest();

  try
  {
    JSON_ASSERT_OBJECT(doc);
    JSON_ASSERT_CONTAINS(doc, JSON_DIGEST);
    JSON_ASSERT_OBJECT(doc[JSON_DIGEST]);
    const rapidjson::Value& digest_block = doc[JSON_DIGEST];
    {
      JSON_GET_STRING_MEMBER(digest_block, JSON_HA1, digest->_ha1);
      // The QoP is assumed to always be 'auth'.
      JSON_GET_STRING_MEMBER(digest_block, JSON_REALM, digest->_realm);
    }

    JSON_GET_STRING_MEMBER(doc, JSON_OPAQUE, digest->_opaque);
    JSON_GET_STRING_MEMBER(doc, JSON_IMPU, digest->_impu);
    JSON_GET_INT_MEMBER(doc, JSON_NC, digest->_nonce_count);
  }
  catch(JsonFormatError err)
  {
    TRC_INFO("Failed to deserialize JSON document (hit error at %s:%d)",
             err._file, err._line);
    delete digest; digest = NULL;
  }

  return digest;
}

std::string AuthStore::JsonSerializerDeserializer::name()
{
  return "JSON";
}
