#include "call_list_xml.h"
#include <set>

typedef CallListStore::CallFragment::Type FragmentType;

std::string xml_from_call_records(const std::vector<CallListStore::CallFragment>& records)
{
  std::map<std::string, std::string> ids_to_records;
  std::vector<std::string> ordered_ids;
  std::set<std::string> completed_ids;
  for (std::vector<CallListStore::CallFragment>::const_iterator ii = records.begin();
       ii != records.end();
       ii++)
  {
    std::string record_id = ii->id;
    std::string record = ii->contents;

    if ((ii->type == FragmentType::BEGIN) && !ids_to_records[record_id].empty() )
    {
      LOG_WARNING("BEGIN marker found with ID %s but there is an earlier entry for this ID", ii->id.c_str());
    }
    else if ((ii->type == FragmentType::REJECTED) && !ids_to_records[record_id].empty())
    {
      LOG_WARNING("REJECTED marker found with ID %s but there is an earlier entry for this ID", ii->id.c_str());
    }
    else if ((ii->type == FragmentType::END) && ids_to_records[record_id].empty())
    {
      LOG_WARNING("END marker found with ID %s but there is no earlier entry for this ID", ii->id.c_str());
    }
    else if ((ii->type == FragmentType::END) && (completed_ids.find(ii->id) != completed_ids.end()))
    {
      LOG_WARNING("END marker found with ID %s but there is already a complete record for this ID", ii->id.c_str());
    }
    else
    {
      ids_to_records[record_id].append(record);

      // Keep calls in the order of the first event
      if ((ii->type == FragmentType::BEGIN) || (ii->type == FragmentType::REJECTED))
      {
        ordered_ids.push_back(record_id);
      }

      // Track which call records are completed so we don't display
      // ones that are just a BEGIN
      if ((ii->type == FragmentType::END) || (ii->type == FragmentType::REJECTED))
      {
        completed_ids.insert(record_id);
      }

    }
  }

  std::string final_xml = "<call-list><calls>";
  for (std::vector<std::string>::const_iterator ii = ordered_ids.begin();
       ii != ordered_ids.end();
       ii++)
  {
    if (completed_ids.find(*ii) != completed_ids.end())
    {
      final_xml.append("<call>");
      final_xml.append(ids_to_records[*ii]);
      final_xml.append("</call>");
    }
    else
    {
      LOG_WARNING("Call record %s is only a partial record", ii->c_str());
    }
  }

  final_xml.append("</calls></call-list>");

  return final_xml;
}
