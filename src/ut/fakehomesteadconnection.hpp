/**
 * @file fakehomesteadconnection.hpp .
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef FAKEHOMESTEADCONNECTION_H__
#define FAKEHOMESTEADCONNECTION_H__

#include <string>
#include "sas.h"
#include "homesteadconnection.h"

/// HomesteadConnection that writes to/reads from a local map rather than Homestead
class FakeHomesteadConnection : public HomesteadConnection
{
public:
  FakeHomesteadConnection();
  ~FakeHomesteadConnection();

  void flush_all();

  void set_result(const std::string& url, const std::vector<std::string> result);
  void delete_result(const std::string& url);
  void set_rc(const std::string& url, long rc);
  void delete_rc(const std::string& url);

private:
  long get_digest_and_parse(const std::string& path, std::string& digest, std::string& realm, SAS::TrailId trail);
  std::map<std::string, std::vector<std::string>> _results;
  std::map<std::string, long> _rcs;
};

#endif
