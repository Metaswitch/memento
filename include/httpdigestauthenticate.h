/**
 * @file httpdigestauthenticate.h  Definition of class for storing Authentication Vectors
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

class HTTPDigestAuthenticate
{
public:
  struct Response
  {
    Response(std::string username, std::string realm, std::string nonce,
             std::string uri, std::string qop, std::string nc,
             std::string cnonce, std::string response, std::string opaque) :
      _username(username), _realm(realm), _nonce(nonce),
      _uri(uri), _qop(qop), _nc(nc),
      _cnonce(cnonce), _response(response), _opaque(opaque)
      {}

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

  HTTPDigestAuthenticate(AuthStore *auth_store, 
                         HomesteadConnection *homestead_conn,
                         std::string home_domain);

  virtual ~HTTPDigestAuthenticate();

  HTTPCode authenticate_request(const std::string impu, 
                                std::string authorization_header, 
                                std::string& www_auth_header, 
                                SAS::TrailId trail);
  HTTPCode check_auth_info(std::string authorization_header);
  HTTPCode retrieve_digest();
  HTTPCode request_store_digest(bool include_stale);
  HTTPCode check_if_matches();
  void generate_digest(std::string ha1);
  std::string generate_www_auth_header(bool include_stale);
  HTTPCode parse_authenticate(std::string auth_header);

  AuthStore* _auth_store;
  HomesteadConnection* _homestead_conn;
  std::string _home_domain;

  std::string _impu;
  SAS::TrailId _trail;
  std::string _impi;
  bool _auth_info;
  AuthStore::Digest* _digest;
  Response* _response;
  std::string _header;
};

#endif
