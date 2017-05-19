/**
 * @file call_list_xml.h XML processing for call lists.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef CALL_LIST_STORE_XML_H_
#define CALL_LIST_STORE_XML_H_

#include "call_list_store.h"
#include "log.h"
#include <vector>
#include <map>
#include <string>

/// Converts a list of CallFragments retrieved from the store into
/// valid XML.
///
/// @param records  - The list of records to generate XML from. No
///                   ordering is assumed.
/// @param trail    - The SAS trail ID for logging.
std::string xml_from_call_records(const std::vector<CallListStore::CallFragment>& records, SAS::TrailId trail);

#endif
