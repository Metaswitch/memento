/**
 * @file fakehomesteadconnection.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "fakehomesteadconnection.hpp"
#include "gtest/gtest.h"

FakeHomesteadConnection::FakeHomesteadConnection() :
  // Pass NULL in as the HTTP resolver.  This will never get invoked amnyway.
  HomesteadConnection("narcissus", NULL, NULL, NULL)
{
}


FakeHomesteadConnection::~FakeHomesteadConnection()
{
  flush_all();
}


void FakeHomesteadConnection::flush_all()
{
  _results.clear();
  _rcs.clear();
}

void FakeHomesteadConnection::set_result(const std::string& url,
                                         const std::vector<std::string> result)
{
  _results[url] = result;
}

void FakeHomesteadConnection::delete_result(const std::string& url)
{
  _results.erase(url);
}

void FakeHomesteadConnection::set_rc(const std::string& url,
                                     long rc)
{
  _rcs[url] = rc;
}


void FakeHomesteadConnection::delete_rc(const std::string& url)
{
  _rcs.erase(url);
}

long FakeHomesteadConnection::get_digest_and_parse(const std::string& path,
                                                   std::string& digest,
                                                   std::string& realm,
                                                   SAS::TrailId trail)
{
  HTTPCode http_code = HTTP_NOT_FOUND;
  std::map<std::string, std::vector<std::string>>::const_iterator i = _results.find(path);
  if (i != _results.end())
  {
    digest = i->second[0];
    realm = i->second[1];
    http_code = HTTP_OK;
  }

  std::map<std::string, long>::const_iterator i2 = _rcs.find(path);
  if (i2 != _rcs.end())
  {
    http_code = i2->second;
  }

  return http_code;
}
