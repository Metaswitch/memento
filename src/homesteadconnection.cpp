/**
 * @file homesteadconnection.cpp
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "homesteadconnection.h"

#include "httpconnection.h"
#include "mementosasevent.h"
#include <rapidjson/document.h>
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

HomesteadConnection::HomesteadConnection(HttpConnection* connection) :
  _http(connection)
{
}

HomesteadConnection::~HomesteadConnection()
{
}

/// Retrieve user's digest data.
HTTPCode HomesteadConnection::get_digest_data(const std::string& private_user_identity,
                                              const std::string& public_user_identity,
                                              std::string& digest,
                                              std::string& realm,
                                              SAS::TrailId trail)
{
  SAS::Event event(trail, SASEvent::HTTP_HS_DIGEST_LOOKUP, 0);
  event.add_var_param(private_user_identity);
  event.add_var_param(public_user_identity);
  SAS::report_event(event);

  std::string path = "/impi/" +
                     Utils::url_escape(private_user_identity) +
                     "/av?impu=" +
                     Utils::url_escape(public_user_identity);
  HTTPCode rc = get_digest_and_parse(path, digest, realm, trail);

  if (rc != HTTP_OK)
  {
    SAS::Event event(trail, SASEvent::HTTP_HS_DIGEST_LOOKUP_FAILURE, 0);
    event.add_var_param(private_user_identity);
    event.add_var_param(public_user_identity);
    event.add_static_param(rc);
    SAS::report_event(event);
  }
  else
  {
    SAS::Event event(trail, SASEvent::HTTP_HS_DIGEST_LOOKUP_SUCCESS, 0);
    event.add_var_param(private_user_identity);
    event.add_var_param(public_user_identity);
    SAS::report_event(event);
  }

  return rc;
}

/// Parse received digest. This must be valid JSON and have the format:
/// { "digest" : { "ha1": "ha1",
///                "qop": "qop",
///                "realm": "realm" }}
HTTPCode HomesteadConnection::get_digest_and_parse(const std::string& path,
                                                   std::string& digest,
                                                   std::string& realm,
                                                   SAS::TrailId trail)
{
  HttpResponse response = _http->create_request(HttpClient::RequestType::GET,
                                                path)
    .set_sas_trail(trail)
    .send();

  HTTPCode rc = response.get_rc();

  if (rc == HTTP_OK)
  {
    std::string json_data = response.get_body();
    rapidjson::Document doc;
    doc.Parse<0>(json_data.c_str());

    if (doc.HasParseError())
    {
      TRC_WARNING("Failed to parse JSON body %s", json_data.c_str());
      rc = HTTP_BAD_REQUEST;
    }
    else if (!doc.HasMember("digest"))
    {
      TRC_WARNING("Returned Digest is invalid. JSON is: %s", json_data.c_str());
      rc = HTTP_BAD_REQUEST;
    }

    if (rc == HTTP_OK)
    {
      rapidjson::Value& digest_v = doc["digest"];

      if (!digest_v.HasMember("ha1"))
      {
        TRC_WARNING("Returned Digest is invalid. JSON is: %s", json_data.c_str());
        rc = HTTP_BAD_REQUEST;
      }
      else if (!digest_v.HasMember("qop"))
      {
        TRC_WARNING("Returned Digest is invalid. JSON is: %s", json_data.c_str());
        rc = HTTP_BAD_REQUEST;
      }
      else if (std::string(digest_v["qop"].GetString()) != "auth")
      {
        TRC_WARNING("Returned Digest is invalid. QoP isn't auth (%s)", digest_v["qop"].GetString());
        rc = HTTP_BAD_REQUEST;
      }
      else if (!digest_v.HasMember("realm"))
      {
        TRC_WARNING("Returned Digest is invalid. JSON is: %s", json_data.c_str());
        rc = HTTP_BAD_REQUEST;
      }
      else
      {
        digest = digest_v["ha1"].GetString();
        realm = digest_v["realm"].GetString();
      }
    }
  }
  else if (rc == HTTP_SERVER_UNAVAILABLE)
  {
    // Change a 503 response to 504 as we don't want to trigger retries -
    // as httpconnection will already have retried for us.
    rc = HTTP_GATEWAY_TIMEOUT;
  }

  return rc;
}
