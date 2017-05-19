/**
 * @file homesteadconnection.h
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef HOMESTEADCONNECTION_H__
#define HOMESTEADCONNECTION_H__

#include "httpconnection.h"
#include "sas.h"

/// @class HomesteadConnection
///
/// Provides a connection to the Homstead service for retrieving digests
class HomesteadConnection
{
public:
  /// Constructor.
  /// @param server           The homestead cluster name to use.
  /// @param resolver         HTTP resolver to use to query homestead.
  /// @param load_monitor     Load monitor monitoring these requests.
  /// @param stats_aggregator Statistics aggregator.
  /// @param comm_monitor     An optional CommunicatorMonitor object to monitor
  ///                         the state of the connection and reports alarms.
  HomesteadConnection(const std::string& server,
                      HttpResolver* resolver,
                      LoadMonitor *load_monitor,
                      CommunicationMonitor* comm_monitor=NULL);

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

  /// Pointer to the underlying http connection manager.
  HttpConnection* _http;
};
#endif
