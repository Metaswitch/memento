/**
 * @file httpdigestauthenticate.h  
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

#ifndef HTTPDIGESTAUTHENTICATE_H_
#define HTTPDIGESTAUTHENTICATE_H_

#include "sas.h"
#include "httpconnection.h"
#include "homesteadconnection.h"
#include "authstore.h"
#include "counter.h"

class HTTPDigestAuthenticate
{
public:
  struct Response
  {
    Response() :
      _username(""), _realm(""), _nonce(""), _uri(""), _qop(""),
       _nc(""), _cnonce(""), _response(""), _opaque("")
      {}

    void set_members(std::string username, std::string realm,
                     std::string nonce, std::string uri, std::string qop,
                     std::string nc, std::string cnonce,
                     std::string response, std::string opaque)
    {
      _username = username;
      _realm = realm;
      _nonce = nonce;
      _uri = uri;
      _qop = qop;
      _nc = nc;
      _cnonce = cnonce;
      _response = response;
      _opaque = opaque;
    }

    std::string _username;
    std::string _realm;
    std::string _nonce;
    std::string _uri;
    std::string _qop;
    std::string _nc;
    std::string _cnonce;
    std::string _response;
    std::string _opaque;
  };

  /// Constructor.
  /// @param auth_store      A pointer to the auth store.
  /// @param homestead_conn  A pointer to the homestead connection object
  /// @param home_domain     Home domain of the deployment
  /// @param stat_*          Statistics
  HTTPDigestAuthenticate(AuthStore *auth_store,
                         HomesteadConnection *homestead_conn,
                         std::string home_domain,
                         Counter* stat_auth_challenge_count,
                         Counter* stat_auth_attempt_count,
                         Counter* stat_auth_success_count,
                         Counter* stat_auth_failure_count,
                         Counter* stat_auth_stale_count);

  /// Destructor.
  virtual ~HTTPDigestAuthenticate();

  /// authenticate_request.
  /// @param impu                  Public ID
  /// @param authorization_header  Authorization header from the request
  /// @param www_auth_header       WWW-Authenticate header to populate
  /// @param method                Method of the request
  /// @param trail                 SAS trail
  HTTPCode authenticate_request(const std::string impu,
                                std::string authorization_header,
                                std::string& www_auth_header,
                                std::string method,
                                SAS::TrailId trail);

private:

  /// check_auth_header
  /// @param authorization_header  Authorization header from the request
  /// @param auth_info             Reference to bool storing if the request contains authorization credentials
  /// @param response              Pointer to response built from authorization header
  HTTPCode check_auth_header(std::string authorization_header, bool& auth_info, Response* response);

  /// retrieve_digest_from_store.
  /// @param www_auth_header       WWW-Authenticate header to populate
  /// @param response              Pointer to response built from authorization header
  HTTPCode retrieve_digest_from_store(std::string& www_auth_header, Response* response);

  /// request_digest_and_store
  /// @param www_auth_header       WWW-Authenticate header to populate
  /// @param include_stale         Whether the WWW-Authenticate should include a stale=TRUE parameter
  /// @param response              Pointer to response built from authorization header
  HTTPCode request_digest_and_store(std::string& www_auth_header, bool include_stale, Response* response);

  /// check_if_matches
  /// @param digest                Pointer to Digest object built from stored digest
  /// @param www_auth_header       WWW-Authenticate header to populate
  /// @param response              Pointer to response built from authorization header
  HTTPCode check_if_matches(AuthStore::Digest* digest, std::string& www_auth_header, Response* response);

  /// generate_digest
  /// @param ha1                   ha1 retrieved from Homestead
  /// @param realm                 Realm of the client request (home domain)
  /// @param digest                Pointer to Digest object built from stored digest
  void generate_digest(std::string ha1, std::string realm, AuthStore::Digest* digest);

  /// generate_www_auth_header
  /// @param www_auth_header       WWW-Authenticate header to populate
  /// @param include_stale         Whether the WWW-Authenticate should include a stale=TRUE parameter
  /// @param digest                Pointer to Digest object built from stored digest
  void generate_www_auth_header(std::string& www_auth_header, bool include_stale, AuthStore::Digest* digest);

  /// parse_auth_header
  /// @param auth_header           Authorization header from the request
  /// @param auth_info             Reference to bool storing if the request contains authorization credentials
  /// @param response              Pointer to response built from authorization header
  HTTPCode parse_auth_header(std::string auth_header, bool& auth_info, Response* response);

  /// set_members
  /// @param impu                  Public ID
  /// @param impi                  Private ID
  /// @param method                Method of the request
  /// @param trail                 SAS trail
  void set_members(std::string impu, std::string method, std::string impi, SAS::TrailId trail);

  AuthStore* _auth_store;
  HomesteadConnection* _homestead_conn;
  std::string _home_domain;

  Counter* _stat_auth_challenge_count;
  Counter* _stat_auth_attempt_count;
  Counter* _stat_auth_success_count;
  Counter* _stat_auth_failure_count;
  Counter* _stat_auth_stale_count;

  std::string _impu;
  SAS::TrailId _trail;
  std::string _impi;
  std::string _method;
};

#endif
