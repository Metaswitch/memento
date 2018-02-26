/**
 * @file homesteadconnection.h
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef HOMESTEADCONNECTION_H__
#define HOMESTEADCONNECTION_H__

#include "httpclient.h"
#include "sas.h"

class HttpConnection;

/// @class HomesteadConnection
///
/// Provides a connection to the Homstead service for retrieving digests
class HomesteadConnection
{
public:
  /// Constructor
  /// @param connection       HTTP connection to use
  HomesteadConnection(HttpConnection* connection);

  /// Destructor
  virtual ~HomesteadConnection();

  /// get_digest_data
  /// @param private_user_identity  A reference to the private user identity.
  /// @param public_user_identity   A reference to the public user identity.
  /// @param digest                 The retrieved digest (as a string)
  /// @param realm                  The retrieved realm (as a string)
  HTTPCode get_digest_data(const std::string& private_user_identity,
                           const std::string& public_user_identity,
                           std::string& digest,
                           std::string& realm,
                           SAS::TrailId trail);
private:
  /// get_digest_and_parse
  /// @param path    The path for the homestead request
  /// @param digest  The retrieved digest (as a string)
  /// @param realm   The retrieved realm (as a string)
  virtual HTTPCode get_digest_and_parse(const std::string& path,
                                        std::string& digest,
                                        std::string& realm,
                                        SAS::TrailId trail);

  HttpConnection* _http;
};
#endif
