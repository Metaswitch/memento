/**
 * @file handlers.h
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

#ifndef HANDLERS_H__
#define HANDLERS_H__

#include "httpstack.h"
#include "httpstack_utils.h"
#include "sas.h"
#include "authstore.h"
#include "homesteadconnection.h"
#include "httpdigestauthenticate.h"
#include "call_list_store.h"

class CallListHandler : public HttpStackUtils::Handler
{
public:
  struct Config
  {
    Config(AuthStore* auth_store,
           HomesteadConnection* homestead_conn,
           CallListStore::Store* call_list_store,
           std::string home_domain) :
    _auth_store(auth_store),
      _homestead_conn(homestead_conn),
      _call_list_store(call_list_store),
      _home_domain(home_domain)
      {}
    AuthStore* _auth_store;
    HomesteadConnection* _homestead_conn;
    CallListStore::Store* _call_list_store;
    std::string _home_domain;
  };

  CallListHandler(HttpStack::Request& req,
                  const Config* cfg,
                  SAS::TrailId trail) :
    HttpStackUtils::Handler(req, trail),
    _cfg(cfg),
    _auth_mod(new HTTPDigestAuthenticate(_cfg->_auth_store,
                                         _cfg->_homestead_conn,
                                         _cfg->_home_domain))
  {};

  ~CallListHandler()
  {
    delete _auth_mod; _auth_mod = NULL;
  }

  void run();
  HTTPCode parse_request();
  HTTPCode authenticate_request();

protected:
  const Config* _cfg;
  HTTPDigestAuthenticate* _auth_mod;
  void respond_when_authenticated();

  std::string _impu;
};

#endif
