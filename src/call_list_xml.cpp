#include "call_list_xml.h"
#include "rapidxml/rapidxml.hpp"
#include <set>

typedef CallListStore::CallFragment::Type FragmentType;

std::string xml_from_call_records(const std::vector<CallListStore::CallFragment>& records)
{
  std::map<std::string, std::vector<CallListStore::CallFragment> > ids_to_records;
  for (std::vector<CallListStore::CallFragment>::const_iterator ii = records.begin();
       ii != records.end();
       ii++)
  {
    std::string record_id = ii->id;
    ids_to_records[record_id].push_back(*ii);
  }

  std::string final_xml = "<call-list><calls>";
  for (std::map<std::string, std::vector<CallListStore::CallFragment> >::const_iterator ii = ids_to_records.begin();
       ii != ids_to_records.end();
       ii++)
  {
    std::string record_id = ii->first;
    std::vector<CallListStore::CallFragment> record_fragments = ii->second;

    if (record_fragments.size() == 1)
    {
      if (record_fragments[0]->type == FragmentType::REJECTED)
      {
        std::string xml = "<call>" + record_fragments[0].contents + "</call>";
        try
        {
          rapidxml::xml_document<> doc;
          doc.parse<parse_non_destructive>(xml);
          final_xml.append(xml);
        }
        catch (rapidxml::parse_error e)
        {
          // error
        }
      }
      else
      {
        LOG_WARNING("Only one entry for call record %s but it was not REJECTED", record_id.c_str());
      }
    }
    else if (record_fragments.size() == 2)
    {
      if ((record_fragments[0]->type == FragmentType::BEGIN) &&
          (record_fragments[1]->type == FragmentType::END))
      {
        std::string xml = "<call>" + record_fragments[0].contents + record_fragments[1].contents + "</call>";
        try
        {
          rapidxml::xml_document<> doc;
          doc.parse<parse_non_destructive>(xml);
          final_xml.append(xml);
        }
        catch (rapidxml::parse_error e)
        {
          // error
        }

        // put it in
      }
      else
      {
        LOG_WARNING("Found two entries for call record %s but it was not a BEGIN followed by an END", record_id.c_str());
      }
    }
    else
    {
      LOG_WARNING("Found %d entries for call record %s, expected 1 (REJECTED) or 2 (BEGIN/END)", record_fragments.size(), record_id.c_str());
    }

  }

  final_xml.append("</calls></call-list>");

  return final_xml;
}
