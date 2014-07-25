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
#include "mementosasevent.h"
#include "call_list_store.h"
#include "call_list_xml.h"

// This handler deals with requests to the call list URL
void CallListHandler::run()
{
  HTTPCode rc = parse_request();

  if (rc != HTTP_OK)
  {
    // LCOV_EXCL_START
    send_http_reply(rc);
    delete this;
    return;
    // LCOV_EXCL_STOP
  }

  LOG_DEBUG("Parsed Call Lists request. Public ID: %s", _impu.c_str());
  SAS::Event rx_event(trail(), SASEvent::CALL_LIST_REQUEST_RX, 0);
  rx_event.add_var_param(_impu);
  SAS::report_event(rx_event);

  std::string www_auth_header;
  std::string auth_header = _req.header("Authorization");
  std::string method = _req.method_as_str();

  rc = _auth_mod->authenticate_request(_impu, auth_header, www_auth_header, method, trail());

  if (rc == HTTP_UNAUTHORIZED)
  {
    LOG_DEBUG("Authorization data missing or out of date, responding with 401");
    _req.add_header("WWW-Authenticate", www_auth_header);
    send_http_reply(rc);
  }
  else if (rc != HTTP_OK)
  {
    LOG_DEBUG("Authorization failed, responding with %d", rc);
    send_http_reply(rc);
  } else {
    respond_when_authenticated();
  }
  delete this;
  return;
}

void CallListHandler::respond_when_authenticated()
{
  std::vector<CallListStore::CallFragment> records;
  CassandraStore::ResultCode db_rc =
    _cfg->_call_list_store->get_call_fragments_sync(_impu, records, trail());

  if (db_rc != CassandraStore::OK)
  {
    SAS::Event db_event(trail(), SASEvent::CALL_LIST_DB_FAILED, 0);
    db_event.add_static_param(db_rc);
    SAS::report_event(db_event);

    LOG_DEBUG("get_call_records_sync failed with result code %d", db_rc);
    send_http_reply(500);
    return;
  }

  SAS::Event db_event(trail(), SASEvent::CALL_LIST_DB_RETRIEVAL, 0);
  db_event.add_static_param(records.size());
  SAS::report_event(db_event);

  // Request has authenticated, so attempt to get the call lists.
  std::string calllists = xml_from_call_records(records);
  _req.add_content(calllists);

  SAS::Event tx_event(trail(), SASEvent::CALL_LIST_RSP_TX, 0);
  tx_event.add_var_param(_impu);
  SAS::report_event(tx_event);

  send_http_reply(HTTP_OK);
}

HTTPCode CallListHandler::parse_request()
{
  const std::string prefix = "/org.projectclearwater.call-list/users/";
  std::string path = _req.path();

  _impu = path.substr(prefix.length(), path.find_first_of("/", prefix.length()) - prefix.length());

  return HTTP_OK;
}
