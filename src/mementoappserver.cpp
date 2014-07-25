/**
 * @file mementoappserver.cpp
 *
 * Project Clearwater - IMS in the cloud.
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
#include "mementoappserver.h"
#include "call_list_store_processor.h"
#include "log.h"
#include "rapidxml/rapidxml.hpp"
#include "rapidxml/rapidxml_print.hpp"
#include "base64.h"
#include <ctime>
#include "utils.h"
#include "mementosasevent.h"

// Values for the load monitor. Target latency is 1 second
static const int TARGET_LATENCY = 1000000;
static const int MAX_TOKENS = 20;
static float INITIAL_TOKEN_RATE = 100.0;
static float MIN_TOKEN_RATE = 10.0;

static const int MAX_CALL_ENTRY_LENGTH = 4096;
static const char* TIMESTAMP_PATTERN = "%Y%m%d%H%M%S";
static const char* XML_PATTERN = "%Y-%m-%dT%H:%M:%S";

// Constants to create the Call list XML
namespace MementoXML
{
  static const char* TO = "to";
  static const char* FROM = "from";
  static const char* NAME = "name";
  static const char* URI = "uri";
  static const char* OUTGOING = "outgoing";
  static const char* ANSWERED = "answered";
  static const char* START_TIME = "start-time";
  static const char* END_TIME = "end-time";
  static const char* ANSWER_TIME = "answer-time";
}

/// Constructor.
MementoAppServer::MementoAppServer(const std::string& _service_name,
                                   const std::string& home_domain,
                                   const int max_call_list_length,
                                   const int memento_threads,
                                   const int call_list_ttl) :
  AppServer(_service_name),
  _home_domain(home_domain),
  _load_monitor(new LoadMonitor(TARGET_LATENCY,
                                MAX_TOKENS,
                                INITIAL_TOKEN_RATE,
                                MIN_TOKEN_RATE)),
  _call_list_store(new CallListStore::Store()), //LCOV_EXCL_LINE
  _call_list_store_processor(new CallListStoreProcessor(_load_monitor,
                                                        _call_list_store,
                                                        max_call_list_length,
                                                        memento_threads,
                                                        call_list_ttl))
{
}

/// Destructor.
MementoAppServer::~MementoAppServer()
{
  delete _load_monitor; _load_monitor = NULL;
  delete _call_list_store; _call_list_store = NULL;
  delete _call_list_store_processor; _call_list_store_processor = NULL;
}

// Returns an AppServerTsx if the load monitor admits the request, and if
// the request is either an INVITE or a BYE.
AppServerTsx* MementoAppServer::get_app_tsx(AppServerTsxHelper* helper,
                                            pjsip_msg* req)
{
  if (!_load_monitor->admit_request())
  {
    // LCOV_EXCL_START
    LOG_WARNING("No available tokens - no memento processing of request");
    return NULL;
    // LCOV_EXCL_STOP
  }

  if ((req->line.req.method.id != PJSIP_INVITE_METHOD) &&
      (req->line.req.method.id != PJSIP_BYE_METHOD))
  {
    // Request isn't an INVITE or BYE, no processing is required.
    return NULL;
  }

  MementoAppServerTsx* memento_tsx = new MementoAppServerTsx(helper);
  memento_tsx->set_members(_load_monitor,
                           _call_list_store_processor,
			   _home_domain);
  return memento_tsx;
}

// Constructor
MementoAppServerTsx::MementoAppServerTsx(AppServerTsxHelper* helper) :
    AppServerTsx(helper),
    _answered(false),
    _incoming(false),
    _start_time(NULL),
    _caller_name(""),
    _caller_uri(""),
    _callee_name(""),
    _callee_uri(""),
    _stored_entry(false),
    _unique_id(""),
    _impu("")
{
}

// Destructor
MementoAppServerTsx::~MementoAppServerTsx() {}

void MementoAppServerTsx::set_members(LoadMonitor* load_monitor,
                                      CallListStoreProcessor* call_list_store_processor,
                                      std::string& home_domain)
{
  _load_monitor = load_monitor;
  _call_list_store_processor = call_list_store_processor;
  _home_domain = home_domain;
}

void MementoAppServerTsx::on_initial_request(pjsip_msg* req)
{
  // Get the current time
  time_t rawtime;
  time(&rawtime);
  _start_time = localtime(&rawtime);

  // Is the call originating or terminating?
  pjsip_route_hdr* hroute = (pjsip_route_hdr*)pjsip_msg_find_hdr(req,
                                                                 PJSIP_H_ROUTE,
                                                                 NULL);

  if (hroute != NULL)
  {
    pjsip_sip_uri* uri = (pjsip_sip_uri*)hroute->name_addr.uri;
    const pj_str_t ORIG = pj_str((char*)"orig");
    pjsip_param* orig_param = pjsip_param_find(&uri->other_param, &ORIG);
    _incoming = (orig_param != NULL);
  }

  // Get the caller, callee and impu values
  if (_incoming)
  {
    // Get the callee's URI amd name from the To header.
    _callee_uri = uri_to_string(PJSIP_URI_IN_FROMTO_HDR,
                    (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri));
    _callee_name = pj_str_to_string(&((pjsip_name_addr*)
                                       (PJSIP_MSG_TO_HDR(req)->uri))->display);

    // Get the caller's URI and name from the P-Asserted Identity header. If
    // this is missing, use the From header.
    const pj_str_t P_ASSERTED_IDENTITY = pj_str((char*)"P-Asserted-Identity");
    pjsip_routing_hdr* asserted_id = (pjsip_routing_hdr*)
               pjsip_msg_find_hdr_by_name(req, &P_ASSERTED_IDENTITY, NULL);

    if (asserted_id != NULL)
    {
      _caller_uri = uri_to_string(PJSIP_URI_IN_FROMTO_HDR,
                       (pjsip_uri*)pjsip_uri_get_uri(&asserted_id->name_addr));
      _caller_name = pj_str_to_string(&asserted_id->name_addr.display);
    }
    else
    {
      _caller_uri = uri_to_string(PJSIP_URI_IN_FROMTO_HDR,
                 (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_FROM_HDR(req)->uri));
      _caller_name = pj_str_to_string(&((pjsip_name_addr*)
                                    (PJSIP_MSG_FROM_HDR(req)->uri))->display);
    }

    // Set the IMPU equal to the caller's URI
    _impu = _caller_uri;
  }
  else
  {
    // Get the callee's URI from the request URI. There can be no name value.
    _callee_uri =  uri_to_string(PJSIP_URI_IN_FROMTO_HDR, req->line.req.uri);

    // Get the caller's URI and name from the From header.
    _caller_uri = uri_to_string(PJSIP_URI_IN_FROMTO_HDR,
                (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_FROM_HDR(req)->uri));
    _callee_name = pj_str_to_string(&((pjsip_name_addr*)
                                   (PJSIP_MSG_FROM_HDR(req)->uri))->display);

    // Set the IMPU equal to the callee's URI
    _impu = _callee_uri;
  }

  // Add a unique ID containing the IMPU to the record route header.
  // This has the format:
  //     <YYYYMMDDHHMMSS>_<unique_id>-<base64 encoded impu>@memento.<home domain>
  std::string timestamp = create_formatted_timestamp(_start_time, TIMESTAMP_PATTERN);
  _unique_id = std::to_string(Utils::generate_unique_integer(0,0));
  std::string encoded_impu = base64_encode(reinterpret_cast<const unsigned char*>
                                            (_impu.c_str()), _impu.length());
  std::string decoded_impu = base64_decode(encoded_impu);
  std::string prefix = timestamp.append("_").append(_unique_id).append("-").
                append(encoded_impu).append("@memento.").append(_home_domain);

  add_to_dialog(prefix);
  forward_request(req);
}

void MementoAppServerTsx::on_in_dialog_request(pjsip_msg* req)
{
  // Get the prefix containing the unique id, start time and IMPU from
  // the top route header.
  std::string header = "";
  pjsip_route_hdr* first_route_hdr = (pjsip_route_hdr*) pjsip_msg_find_hdr(
                                                    req, PJSIP_H_ROUTE, NULL);

  if (first_route_hdr)
  {
    pjsip_uri* route_uri = first_route_hdr->name_addr.uri;
    header = uri_to_string(PJSIP_URI_IN_ROUTING_HDR,route_uri);
    std::string sip = "sip:";
    size_t sip_pos = _impu.find(sip);
    if (sip_pos != std::string::npos)
    {
      header = header.substr(sip_pos + sip.length(), std::string::npos);
    }
  }

  std::vector<std::string> prefix;
  Utils::split_string(header, '_', prefix, 2, false);

  if (prefix.size() != 2)
  {
    LOG_WARNING("Invalid header (%s), can't find unique ID", header.c_str());
    forward_request(req);
    return;
  }

  _unique_id = prefix[0];

  std::vector<std::string> unique_id;
  Utils::split_string(prefix[0], '-', unique_id, 2, false);

  if (unique_id.size() != 2)
  {
    LOG_WARNING("Invalid header (%s), can't find timestamp", header.c_str());
    forward_request(req);
    return;
  }

  std::string timestamp = unique_id[0];

  std::vector<std::string> impu;
  Utils::split_string(prefix[1], '@', impu, 2, false);

  if (impu.size() != 2)
  {
    LOG_WARNING("Invalid header (%s), can't find IMPU", header.c_str());
    forward_request(req);
    return;
  }

  std::string test = base64_encode(reinterpret_cast<const unsigned char*>
                                                   (impu[0].c_str()), impu[0].length());
  _impu = base64_decode(impu[0]);

  // Create the XML. XML should be of the form:
  //   <end-time><current time></end-time>

  // Get the current time
  time_t currenttime;
  time(&currenttime);
  tm* ct = localtime(&currenttime);

  // Create the XML
  rapidxml::xml_document<> doc;
  std::string end_timestamp = create_formatted_timestamp(ct, XML_PATTERN);

  rapidxml::xml_node<>* root = doc.allocate_node(
                                  rapidxml::node_element,
                                  MementoXML::END_TIME,
                                  doc.allocate_string(end_timestamp.c_str()));
  doc.append_node(root);

  char contents[MAX_CALL_ENTRY_LENGTH] = {0};
  char* end = rapidxml::print(contents, doc);
  *end = 0;

  // Write the call list entry to the call list store.
  SAS::Event event(trail(), SASEvent::CALL_LIST_END_FRAGMENT, 0);
  event.add_var_param(_impu);
  event.add_var_param(contents);
  SAS::report_event(event);

  // Write the XML to cassandra (using a different thread)
  _call_list_store_processor->write_call_list_entry(
                                        _impu,
                                        timestamp,
                                        _unique_id,
                                        CallListStore::CallFragment::Type::END,
                                        contents,
                                        trail());

  forward_request(req);
}

void MementoAppServerTsx::on_response(pjsip_msg* rsp, int fork_id)
{
  if (_stored_entry)
  {
    LOG_DEBUG("Already received a final response, no further processing");
    forward_response(rsp);
    return;
  }

  if (rsp->line.status.code < 200)
  {
    // Non-final response; do nothing
    forward_response(rsp);
    return;
  }
  else
  {
     _stored_entry = true;
  }

  // Create the XML. The XML should have the format:
  //  <to>
  //    <URI>_callee_uri</URI>
  //    <name>_callee_name</name> - may be absent
  //  </to>
  //  <from>
  //    <URI>_caller_uri</URI>
  //    <name>_caller_name</name> - may be absent
  //  </from>
  //  <answered>_answered</answered>
  //  <outgoing>_incoming</outgoing>
  //  <start-time>_start_time</start-time>
  //  <answer-time><current time></answer-time> - Only present if
  //                                              call was answered
  rapidxml::xml_document<> doc;

  // Fill in the 'to' values from the callee values.
  rapidxml::xml_node<>* to = doc.allocate_node(rapidxml::node_element,
                                               MementoXML::TO);
  rapidxml::xml_node<>* to_uri = doc.allocate_node(
                                      rapidxml::node_element,
                                      MementoXML::URI,
                                      doc.allocate_string(_callee_uri.c_str()));
  to->append_node(to_uri);

  if (_callee_name != "")
  {
    rapidxml::xml_node<>* to_name = doc.allocate_node(
                                      rapidxml::node_element,
				      MementoXML::NAME,
                                      doc.allocate_string(_callee_name.c_str()));
    to->append_node(to_name);
  }

  doc.append_node(to);

  // Fill in the 'from' values from the caller values.
  rapidxml::xml_node<>* from = doc.allocate_node(rapidxml::node_element,
                                                 MementoXML::FROM);
  rapidxml::xml_node<>* from_uri = doc.allocate_node(
                                        rapidxml::node_element,
					MementoXML::URI,
                                        doc.allocate_string(_caller_uri.c_str()));
  from->append_node(from_uri);

  if (_caller_name != "")
  {
    rapidxml::xml_node<>* from_name = doc.allocate_node(
                                        rapidxml::node_element,
					MementoXML::NAME,
					doc.allocate_string(_caller_name.c_str()));
    from->append_node(from_name);
  }

  doc.append_node(from);

  // Set outgoing to 0 if the call is incoming, and 1 otherwise.
  std::string incoming_str = _incoming ? "0" : "1";
  rapidxml::xml_node<>* incoming = doc.allocate_node(
                                         rapidxml::node_element,
					 MementoXML::OUTGOING,
                                         doc.allocate_string(incoming_str.c_str()));
  doc.append_node(incoming);

  std::string start_timestamp = create_formatted_timestamp(_start_time,
                                                           XML_PATTERN);
  // Set the start time.
  rapidxml::xml_node<>* start_time = doc.allocate_node(
                                      rapidxml::node_element,
                                      MementoXML::START_TIME,
                                      doc.allocate_string(start_timestamp.c_str()));
  doc.append_node(start_time);

  CallListStore::CallFragment::Type type = CallListStore::CallFragment::Type::BEGIN;

  if (rsp->line.status.code >= 300)
  {
    // If the call was rejected, set answered to 1.
    rapidxml::xml_node<>* answered = doc.allocate_node(rapidxml::node_element,
                                                       MementoXML::ANSWERED,
                                                       "1");
    doc.append_node(answered);
    type = CallListStore::CallFragment::Type::REJECTED;
  }
  else
  {
    // If the call was rejected, set answered to 0. Also fill in the answer time
    // with the current time.
    rapidxml::xml_node<>* answered = doc.allocate_node(rapidxml::node_element,
                                                       MementoXML::ANSWERED,
                                                       "0");
    doc.append_node(answered);

    time_t currenttime;
    time(&currenttime);
    tm* ct = localtime(&currenttime);
    std::string answer_timestamp = create_formatted_timestamp(ct, XML_PATTERN);
    rapidxml::xml_node<>* answer_time = doc.allocate_node(
                                      rapidxml::node_element,
                                      MementoXML::ANSWER_TIME,
                                      doc.allocate_string(answer_timestamp.c_str()));
    doc.append_node(answer_time);
  }

  char contents[MAX_CALL_ENTRY_LENGTH] = {0};
  char* end = rapidxml::print(contents, doc);
  *end = 0;

  // Log to SAS
  if (type == CallListStore::CallFragment::Type::BEGIN)
  {
    SAS::Event event(trail(), SASEvent::CALL_LIST_BEGIN_FRAGMENT, 0);
    event.add_var_param(_impu);
    event.add_var_param(contents);
    SAS::report_event(event);
  }
  else
  {
    SAS::Event event(trail(), SASEvent::CALL_LIST_REJECTED_FRAGMENT, 0);
    event.add_var_param(_impu);
    event.add_var_param(contents);
    SAS::report_event(event);
  }

  // Write the XML to cassandra (using a different thread)
  _call_list_store_processor->write_call_list_entry(
                    _impu,
                    create_formatted_timestamp(_start_time, TIMESTAMP_PATTERN),
                    _unique_id,
                    type,
                    contents,
                    trail());
  forward_response(rsp);
}

std::string MementoAppServerTsx::create_formatted_timestamp(tm* timestamp,
                                                            const char* pattern)
{
  char formatted_time[80];
  std::strftime(formatted_time, 80, pattern, timestamp);
  return std::string(formatted_time);
}

std::string MementoAppServerTsx::uri_to_string(pjsip_uri_context_e context,
                                               const pjsip_uri* uri)
{
  int uri_clen = 0;
  char uri_cstr[500];
  if (uri != NULL)
  {
    uri_clen = pjsip_uri_print(context, uri, uri_cstr, sizeof(uri_cstr));
  }
  return std::string(uri_cstr, uri_clen);
}

std::string MementoAppServerTsx::pj_str_to_string(const pj_str_t* pjstr)
{
  return ((pjstr != NULL) && (pj_strlen(pjstr) > 0)) ?
           std::string(pj_strbuf(pjstr), pj_strlen(pjstr)) : std::string("");
}

