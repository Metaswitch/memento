#include "call_list_xml.h"
#include "mementosasevent.h"
#include "rapidxml/rapidxml.hpp"
#include <set>

typedef CallListStore::CallFragment::Type FragmentType;

static bool is_valid_xml(std::string xml, std::string record_id, SAS::TrailId trail)
{
  bool rc = false;
  // Check that the XML is valid and warn if not
  try
  {
    rapidxml::xml_document<> doc;
    doc.parse<rapidxml::parse_non_destructive>((char*)xml.c_str());
    rc = true;
  }
  catch (rapidxml::parse_error e)
  {
    SAS::Event bad_xml_event(trail, SASEvent::CALL_LIST_DB_BAD_XML, 0);
    bad_xml_event.add_var_param(record_id);
    bad_xml_event.add_var_param(e.what());
    bad_xml_event.add_var_param(xml);
    SAS::report_event(bad_xml_event);
    LOG_ERROR("XML parsing error '%s' - trying to parse '%s' for record ID %s",
              e.what(),
              xml.c_str(),
              record_id.c_str());
  }
  return rc;
}

std::string xml_from_call_records(const std::vector<CallListStore::CallFragment>& records, SAS::TrailId trail)
{
  std::map<std::string, std::vector<CallListStore::CallFragment> > ids_to_records;

  // Re-order into a map sorted by record ID
  for (std::vector<CallListStore::CallFragment>::const_iterator ii = records.begin();
       ii != records.end();
       ii++)
  {
    std::string record_id = ii->id;
    ids_to_records[record_id].push_back(*ii);
  }

  // Build an XML document from the valid call records, discarding any
  // that aren't a single REJECTED, a BEGIN/END pair, or which have
  // invalid XML.
  std::string final_xml = "<call-list><calls>";
  for (std::map<std::string, std::vector<CallListStore::CallFragment> >::const_iterator ii = ids_to_records.begin();
       ii != ids_to_records.end();
       ii++)
  {
    std::string record_id = ii->first;
    std::vector<CallListStore::CallFragment> record_fragments = ii->second;

    if (record_fragments.size() == 1)
    {
      // REJECTED is the only record type where having one fragment is valid
      if (record_fragments[0].type == FragmentType::REJECTED)
      {
        std::string xml = "<call>" + record_fragments[0].contents + "</call>";

        if (is_valid_xml(xml, record_id, trail))
        {
          final_xml.append(xml);
        }
      }
      else
      {
        SAS::Event invalid_record(trail, SASEvent::CALL_LIST_DB_INVALID_RECORD_1, 0);
        invalid_record.add_var_param(record_id);
        invalid_record.add_static_param(record_fragments[0].type);
        SAS::report_event(invalid_record);

        LOG_WARNING("Only one entry for call record %s but it was not REJECTED", record_id.c_str());
      }
    }
    else if (record_fragments.size() == 2)
    {
      // If it's not a REJECTED record, it must be BEGIN and END
      if ((record_fragments[0].type == FragmentType::BEGIN) &&
          (record_fragments[1].type == FragmentType::END))
      {
        std::string xml = "<call>" + record_fragments[0].contents + record_fragments[1].contents + "</call>";
        if (is_valid_xml(xml, record_id, trail))
        {
          final_xml.append(xml);
        }
      }
      else
      {
        SAS::Event invalid_record(trail, SASEvent::CALL_LIST_DB_INVALID_RECORD_2, 0);
        invalid_record.add_var_param(record_id);
        invalid_record.add_static_param(record_fragments[0].type);
        invalid_record.add_static_param(record_fragments[1].type);
        SAS::report_event(invalid_record);

        LOG_WARNING("Found two entries for call record %s but it was not a BEGIN followed by an END",
                    record_id.c_str());
      }
    }
    else
    {
      SAS::Event invalid_record(trail, SASEvent::CALL_LIST_DB_INVALID_RECORD, 0);
      invalid_record.add_var_param(record_id);
      invalid_record.add_static_param(record_fragments.size());
      SAS::report_event(invalid_record);

      LOG_WARNING("Found %d entries for call record %s, expected 1 (REJECTED) or 2 (BEGIN/END)",
                  record_fragments.size(),
                  record_id.c_str());
    }

  }

  final_xml.append("</calls></call-list>");

  return final_xml;
}

