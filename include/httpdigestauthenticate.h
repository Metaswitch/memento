/**
 * @file httpdigestauthenticate.h  
 *
 * Copyright (C) Metaswitch Networks 2014
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
