/**
 * @file mockauthstore.h Mock authentication store object.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCKAUTHSTORE_H_
#define MOCKAUTHSTORE_H_

#include "gmock/gmock.h"

#include "authstore.h"

class MockAuthStore : public AuthStore
{
  MockAuthStore() : AuthStore(NULL, 300) {}
  virtual ~MockAuthStore() {}

  MOCK_METHOD4(set_digest, Store::Status(const std::string&,
                                         const std::string&,
                                         const Digest*,
                                         SAS::TrailId));
  MOCK_METHOD4(get_digest, Store::Status(const std::string&,
                                         const std::string&,
                                         Digest*&,
                                         SAS::TrailId));
};

#endif

