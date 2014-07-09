/**
 * @file handlers.cpp handlers for memento
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

#include "handlers.h"
#include "httpdigestauthenticate.h"

// The poll_memento script pings memento to check it's still alive.
// Handle the ping.
void PingHandler::run()
{
  _req.add_content("OK");
  send_http_reply(200);
  delete this;
}

// This handler deals with requests to the call list URL
void CallListHandler::run()
{
  HTTPCode rc = parse_request();
 
  if (rc != HTTP_OK)
  {
    send_http_reply(rc);
    delete this;
    return;
  }

  LOG_DEBUG("Parsed Call Lists request. Public ID: %s", _impu.c_str());

  std::string www_auth_header;
  std::string auth_header = _req.header("Authorization");

  rc = _auth_mod->authenticate_request(_impu, auth_header, www_auth_header, trail());

  if (rc == HTTP_UNAUTHORIZED)
  {
    LOG_DEBUG("Authorization data missing or out of date, responding with 401");
    _req.add_header("WWW-Authenticate", www_auth_header);    
    send_http_reply(rc);
    delete this;
    return;
  }
  else if (rc != HTTP_OK)
  {
    LOG_DEBUG("Authorization data invalid, responding with %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }
    
  // Request has authenticated, so attempt to get the call lists. 
  // DUMMY RESPONSE FOR NOW WITH AN EMPTY CALL LIST
  std::string calllists = "<call-list></call-list>";
  _req.add_content(calllists); 
  send_http_reply(HTTP_OK);
  delete this;
  return;
}

HTTPCode CallListHandler::parse_request()
{
  const std::string prefix = "/org.projectclearwater.call-list/users/";
  std::string path = _req.path();

  _impu = path.substr(prefix.length(), path.find_first_of("/", prefix.length()) - prefix.length());

  return HTTP_OK;
}
