std::string xml_from_call_records(const std::vector<CallRecord>& records)
{
  std::map<std::string, std::string> ids_to_records;
  std::vector<std::string> ordered_ids;
  for (std::vector<CallRecord>::const_iterator ii = records.begin();
       ii != records.end();
       ii++)
  {
    std::string record_id = ii->id;
    std::string record = ii->contents;

    if ((ii->type == BEGIN) && !ids_to_records[record_id].empty() )
    {
      LOG_WARNING("BEGIN marker found for call ??? but there is an earlier entry for this call ID");
    }
    else if ((ii->type == REJECTED) && !ids_to_records[record_id].empty())
    {
      LOG_WARNING("REJECTED marker found for call ??? but there is an earlier entry for this call ID");
    }
    else if ((ii->type == END) && ids_to_records[record_id].empty())
    {
      LOG_WARNING("END marker found for call ??? but there is no earlier entry for this call ID");
    }
    else
    {
      ids_to_records[record_id].append(record);
      if (ii->type == BEGIN)
      {
        ordered_ids.push_back(record_id);
      }
    }
  }

  std::string final_xml = "<call-list><calls>";
  for (std::vector<std::string>::const_iterator ii = ordered_ids.begin();
       ii != ordered_ids.end();
       ii++)
  {
    final_xml.append("<call>");
    final_xml.append(*ii);
    final_xml.append("</call>");
  }

  final_xml.append("</calls></call-list>");

  return final_xml;
}
