/**
 * @file httpdigestauthenticate.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014 Metaswitch Networks Ltd
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

#include "httpdigestauthenticate.h"
#include <openssl/md5.h>
#include "mementosasevent.h"
#include <time.h>

HTTPDigestAuthenticate::HTTPDigestAuthenticate(AuthStore* auth_store,
                                               HomesteadConnection* homestead_conn,
                                               std::string home_domain) :
  _auth_store(auth_store),
  _homestead_conn(homestead_conn),
  _home_domain(home_domain),
  _impu(""),
  _trail(0),
  _impi(""),
  _auth_info(false),
  _digest(NULL),
  _response(NULL)
{
}

HTTPDigestAuthenticate::~HTTPDigestAuthenticate()
{
  delete _digest; _digest = NULL;
  delete _response; _response = NULL;
}

// LCOV_EXCL_START - The components of this function are tested separately
HTTPCode HTTPDigestAuthenticate::authenticate_request(const std::string impu,
                                                      std::string authorization_header,
                                                      std::string& www_auth_header,
                                                      SAS::TrailId trail)
{
  _impu = impu;
  _trail = trail;

  // Check whether the request containing authorization information
  HTTPCode rc = check_auth_info(authorization_header);

  // The authorization header was invalid
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // If there's a full authorization header, attempt to retrieve the digest
  // from memcached. If not, request the digest from Homestead.
  if (_auth_info)
  {
    SAS::Event event(trail, SASEvent::NO_AUTHENTICATION_PRESENT, 0);
    SAS::report_event(event);

    rc = retrieve_digest();
  }
  else
  {
    SAS::Event event(trail, SASEvent::AUTHENTICATION_PRESENT, 0);
    event.add_var_param(authorization_header);
    SAS::report_event(event);

    rc = request_store_digest(false);
  }

  www_auth_header = _header;
  return rc;
}
// LCOV_EXCL_STOP

HTTPCode HTTPDigestAuthenticate::check_auth_info(std::string authorization_header)
{
  HTTPCode rc = HTTP_OK;

  if (authorization_header == "")
  {
    // No authorization information present. Default the private ID from the pub
    // public ID
    LOG_DEBUG("No authorization header present");

    _auth_info = false;

    std::string sip = "sip:";
    size_t sip_pos = _impu.find(sip);
    if (sip_pos != std::string::npos)
    {
      _impi = _impu.substr(sip_pos + sip.length(), std::string::npos);
    }
    else
    {
      LOG_DEBUG("Private ID can't be derived from the public ID (%s)", _impu.c_str());
      rc = HTTP_BAD_RESULT;
    }
  }
  else
  {
    // Check header is valid. Header should contain a username, realm, nonce, uri,
    // qop, nc, cnonce, response, opaque or only a username.
    LOG_DEBUG("Authorization header present: %s", authorization_header.c_str());

    rc = parse_authenticate(authorization_header);

    if (rc == HTTP_OK)
    {
      if (_auth_info)
      {
        if (_response->_qop != "auth")
        {
          LOG_DEBUG("Client requesting non-auth (%s) digest", _response->_qop.c_str());
          return HTTP_BAD_RESULT;
        }

        if (_response->_realm != _home_domain)
        {
          LOG_DEBUG("Request not targeted at the home domain. Target: %s, Home: %s",
                    _response->_realm.c_str(), _home_domain.c_str());
          return HTTP_BAD_RESULT;
        }
      }

      LOG_DEBUG("Authorization header is in a valid form for ID %s", _impi.c_str());
    }
  }

  return rc;
}

HTTPCode HTTPDigestAuthenticate::parse_authenticate(std::string auth_header)
{
  HTTPCode rc = HTTP_OK;

  std::string digest = "Digest";
  size_t digest_pos = auth_header.find(digest);

  if (digest_pos != 0)
  {
    LOG_DEBUG("Authorization header doesn't contain Digest credentials");
    return HTTP_BAD_RESULT;
  }

  std::string rest_of_header = auth_header.substr(digest.length());

  // Split the request on the delimiter ','
  std::vector<std::string> response_params;
  Utils::split_string(rest_of_header, ',', response_params, 0, true, true);

  // Then split by = and sort through array.
  std::map<std::string, std::string> response_key_values;
  std::vector<std::string> temp_value;

  for (std::vector<std::string>::iterator ii = response_params.begin(); ii != response_params.end(); ++ii)
  {
    std::string temp_vec(ii->c_str());
    Utils::split_string(temp_vec, '=', temp_value, 2, true);

    // Strip quotes off befores storing
    int val_len = temp_value[1].length();
    if (val_len > 1 && temp_value[1][0] == '"' && temp_value[1][val_len - 1] == '"')
    {
      temp_value[1] = temp_value[1].substr(1, val_len - 2);
    }

    response_key_values.insert(std::pair<std::string, std::string>(temp_value[0], temp_value[1]));
    temp_value.clear();
  }

  std::string username;
  std::string realm;
  std::string nonce;
  std::string uri;
  std::string qop;
  std::string nc;
  std::string cnonce;
  std::string response;
  std::string opaque;

  std::map<std::string, std::string>::iterator it;

  // A valid Authorization header must contain a username.
  // It must then either contain all of a realm, nonce, uri, qop, nc,
  // cnonce, response and opaque values, or none of the above.
  // It can contain other parameters; these aren't validated.
  it = response_key_values.find("username");
  if (it == response_key_values.end())
  {
    LOG_DEBUG("Authorization header doesn't include a username");
    rc = HTTP_BAD_RESULT;
  }
  else
  {
    username = it->second;
  }

  if (rc == HTTP_OK)
  {
    bool all_present = true;
    bool none_present = true;

    it = response_key_values.find("realm");

    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      realm = it->second;
    }

    it = response_key_values.find("nonce");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      nonce = it->second;
    }

    // LCOV_EXCL_START - no need to check each of these branches in UT
    it = response_key_values.find("uri");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      uri = it->second;
    }

    it = response_key_values.find("qop");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      qop = it->second;
    }

    it = response_key_values.find("nc");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      nc = it->second;
    }

    it = response_key_values.find("cnonce");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      cnonce = it->second;
    }

    it = response_key_values.find("response");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      response = it->second;
    }

    it = response_key_values.find("opaque");
    if (it == response_key_values.end())
    {
      all_present = false;
    }
    else
    {
      none_present = false;
      opaque= it->second;
    }
    // LCOV_EXCL_STOP

    if (all_present)
    {
      LOG_DEBUG("Authorization header valid and complete");
      _impi = username;
      _auth_info = true;
      _response = new Response(username, realm, nonce, uri, qop,
                               nc, cnonce, response, opaque);
    }
    else if (none_present)
    {
      LOG_DEBUG("Authorization header valid and minimal");
      _impi = username;
      _auth_info = false;
    }
    else
    {
      LOG_DEBUG("Authorization header not valid");
      rc = HTTP_BAD_RESULT;
    }
  }

  return rc;
}

HTTPCode HTTPDigestAuthenticate::retrieve_digest()
{
  LOG_DEBUG("Retrieve digest for IMPU: %s, IMPI: %s", _impu.c_str(), _impi.c_str());
  HTTPCode rc = HTTP_OK;

  bool success = _auth_store->get_digest(_impi, _response->_nonce, _digest, _trail);

  if (success)
  {
    // Successfully retrieved digest, so check whether it matches
    // the response sent by the client
    rc = check_if_matches();
  }
  else
  {
    // Digest wasn't found in the store. Request the digest from
    // homestead
    SAS::Event event(_trail, SASEvent::AUTHENTICATION_OUT_OF_DATE, 0);
    SAS::report_event(event);

    rc = request_store_digest(true);
  }

  return rc;
}

// Request a digest from Homestead, store it in memcached, and generate
// the WWW-Authenticate header.
HTTPCode HTTPDigestAuthenticate::request_store_digest(bool include_stale)
{
  HTTPCode rc = HTTP_BAD_RESULT;
  std::string ha1;
  LOG_DEBUG("Request digest for IMPU: %s, IMPI: %s", _impu.c_str(), _impi.c_str());

  // Request the digest from homestead
  rc = _homestead_conn->get_digest_data(_impi, _impu, ha1, _trail);

  if (rc == HTTP_OK)
  {
    // Generate the digest structure and store it in memcached
    LOG_DEBUG("Store digest for IMPU: %s, IMPI: %s", _impu.c_str(), _impi.c_str());
    generate_digest(ha1);
    bool success = _auth_store->set_digest(_impi, _digest->_nonce, _digest, _trail);

    if (success)
    {
      // Create the WWW-Authenticate header
      _header = generate_www_auth_header(include_stale);
      rc = HTTP_UNAUTHORIZED;
    }
    else
    {
      // LCOV_EXCL_START - Store used in UT never fails
      LOG_ERROR("Unable to write digest to store");
      rc = HTTP_SERVER_ERROR;
      // LCOV_EXCL_STOP
    }
  }

  return rc;
}

// Check if the response from the client matches the stored digest
// The logic is:
//   HA1 is the digest returned from Homestead.
//   HA2 = MD5(method : uri), e.g. MD5(“GET:/org.projectclearwater.call-list/users/<IMPU>/call-list.xml)
//   response = MD5(HA1 : nonce : nonce_count (provided by client) : cnonce : qop : HA2)
HTTPCode HTTPDigestAuthenticate::check_if_matches()
{
  HTTPCode rc = HTTP_OK;

  if ((_digest->_opaque != _response->_opaque))
  {
    LOG_DEBUG("The opaque value in the request (%s) doesn't match the stored value (%s)",
              _response->_opaque.c_str(), _digest->_opaque.c_str());
    return HTTP_BAD_RESULT;
  }

  unsigned char ha2[16];
  unsigned char ha2_hex[33];

  MD5_CTX Md5Ctx;
  MD5_Init(&Md5Ctx);
  MD5_Update(&Md5Ctx, "GET", strlen("GET"));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, _response->_uri.c_str(), strlen(_response->_uri.c_str()));
  MD5_Final(ha2, &Md5Ctx);
  Utils::hashToHex(&ha2[0], &ha2_hex[0]);

  unsigned char resp[16];
  unsigned char resp_hex[33];

  MD5_Init(&Md5Ctx);
  MD5_Update(&Md5Ctx, _digest->_ha1.c_str(), strlen(_digest->_ha1.c_str()));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, _response->_nonce.c_str(), strlen(_response->_nonce.c_str()));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, _response->_nc.c_str(), strlen(_response->_nc.c_str()));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, _response->_cnonce.c_str(), strlen(_response->_cnonce.c_str()));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, _response->_qop.c_str(), strlen(_response->_qop.c_str()));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, &ha2_hex, 32);
  MD5_Final(resp, &Md5Ctx);
  Utils::hashToHex(&resp[0], &resp_hex[0]);

  std::string response((const char*) resp_hex);

  if (_response->_response == response)
  {
    LOG_DEBUG("Client response matches stored digest");

    int client_count = atoi(_response->_nc.c_str());

    // Nonce count is stale. Request the digest from Homestead again.
    if (client_count < _digest->_nonce_count)
    {
      LOG_DEBUG("Client response's nonce count is too low");
      SAS::Event event(_trail, SASEvent::AUTHENTICATION_OUT_OF_DATE, 0);
      SAS::report_event(event);

      rc = request_store_digest(true);
    }
    else
    {
      SAS::Event event(_trail, SASEvent::AUTHENTICATION_ACCEPTED, 0);
      SAS::report_event(event);
    }
  }
  else
  {
    // Digest doesn't match - reject the request
    LOG_DEBUG("Client response doesn't match stored digest");
    SAS::Event event(_trail, SASEvent::AUTHENTICATION_REJECTED, 0);
    SAS::report_event(event);

    rc = HTTP_FORBIDDEN;
  }

  return rc;
}

void gen_unique_val(size_t length, std::string& unique_val)
{
  unique_val.reserve(length);

  long timestamp;
  struct timespec spec;
  clock_gettime(CLOCK_REALTIME, &spec);
  timestamp = spec.tv_sec * 1000 + round(spec.tv_nsec / 1000000);

  unique_val = std::to_string(timestamp);

  std::string token;
  Utils::create_random_token(length - unique_val.length(), token);
  unique_val += token;
}

// Populate the Digest, including generating the nonce
void HTTPDigestAuthenticate::generate_digest(std::string ha1)
{
  _digest = new AuthStore::Digest();
  _digest->_ha1 = ha1;
  _digest->_impi = _impi;
  _digest->_realm = _home_domain;

  // TODO add the nonce as a correlator for SAS.
  gen_unique_val(32, _digest->_nonce);
  gen_unique_val(32, _digest->_opaque);
}

// Generate a WWW-Authenticate header. This has the format:
// WWW-Authenticate: Digest realm="<home domain>",
//                          qop="auth",
//                          nonce="<nonce>",
//                          opaque="<opaque>",
//                          [stale=TRUE]
std::string HTTPDigestAuthenticate::generate_www_auth_header(bool include_stale)
{
  std::string header = "Digest";
  header.append(" realm=").append(_home_domain);
  header.append(",qop=").append("auth");
  header.append(",nonce=").append(_digest->_nonce);
  header.append(",opaque=").append(_digest->_opaque);

  if (include_stale)
  {
    header.append(",stale=TRUE");
  }

  LOG_DEBUG("WWW-Authenticate header generated: %s", header.c_str());
  return header;
}
