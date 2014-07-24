#ifndef CALL_LIST_STORE_XML_H_
#define CALL_LIST_STORE_XML_H_

#include "call_list_store.h"
#include "log.h"
#include <vector>
#include <map>
#include <string>

std::string xml_from_call_records(const std::vector<CallListStore::CallFragment>& records, SAS::TrailId trail);

#endif
