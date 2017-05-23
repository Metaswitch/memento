/**
 * @file handlers.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef HANDLERS_H__
#define HANDLERS_H__

#include "httpstack.h"
#include "httpstack_utils.h"
#include "sas.h"
#include "authstore.h"
#include "homesteadconnection.h"
#include "httpdigestauthenticate.h"
#include "call_list_store.h"
#include "counter.h"
#include "accumulator.h"
#include "health_checker.h"

class CallListTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(AuthStore* auth_store,
           HomesteadConnection* homestead_conn,
           CallListStore::Store* call_list_store,
           std::string home_domain,
           LastValueCache* stats_aggregator,
           HealthChecker* hc,
           std::string api_key) :
      _auth_store(auth_store),
      _homestead_conn(homestead_conn),
      _call_list_store(call_list_store),
      _home_domain(home_domain),
      _health_checker(hc),
      _api_key(api_key)
    {
      _stat_auth_challenge_count = new StatisticCounter("auth_challenges",
                                                        stats_aggregator);
      _stat_auth_attempt_count = new StatisticCounter("auth_attempts",
                                                      stats_aggregator);
      _stat_auth_success_count = new StatisticCounter("auth_successes",
                                                      stats_aggregator);
      _stat_auth_failure_count = new StatisticCounter("auth_failures",
                                                      stats_aggregator);
      _stat_auth_stale_count = new StatisticCounter("auth_stales",
                                                    stats_aggregator);
      _stat_cassandra_read_latency = new StatisticAccumulator("cassandra_read_latency",
                                                              stats_aggregator);
      _stat_record_size = new StatisticAccumulator("record_size",
                                                   stats_aggregator);
      _stat_record_length = new StatisticAccumulator("record_length",
                                                     stats_aggregator);
    }

    ~Config()
    {
      delete _stat_auth_challenge_count;
      delete _stat_auth_attempt_count;
      delete _stat_auth_success_count;
      delete _stat_auth_failure_count;
      delete _stat_auth_stale_count;
      delete _stat_cassandra_read_latency;
      delete _stat_record_size;
      delete _stat_record_length;
    }

    AuthStore* _auth_store;
    HomesteadConnection* _homestead_conn;
    CallListStore::Store* _call_list_store;
    std::string _home_domain;
    HealthChecker* _health_checker;
    std::string _api_key;
    StatisticCounter* _stat_auth_challenge_count;
    StatisticCounter* _stat_auth_attempt_count;
    StatisticCounter* _stat_auth_success_count;
    StatisticCounter* _stat_auth_failure_count;
    StatisticCounter* _stat_auth_stale_count;
    StatisticAccumulator* _stat_cassandra_read_latency;
    StatisticAccumulator* _stat_record_size;
    StatisticAccumulator* _stat_record_length;
  };

  CallListTask(HttpStack::Request& req,
               const Config* cfg,
               SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail),
    _cfg(cfg),
    _auth_mod(new HTTPDigestAuthenticate(_cfg->_auth_store,
                                         _cfg->_homestead_conn,
                                         _cfg->_home_domain,
                                         _cfg->_stat_auth_challenge_count,
                                         _cfg->_stat_auth_attempt_count,
                                         _cfg->_stat_auth_success_count,
                                         _cfg->_stat_auth_failure_count,
                                         _cfg->_stat_auth_stale_count))
  {};

  ~CallListTask()
  {
    delete _auth_mod; _auth_mod = NULL;
  }

  void run();
  HTTPCode parse_request();
  HTTPCode authenticate_request();

  /// Gets the user part of an IMPU (expected to be a SIP URI).  
  ///
  /// @param impu            IMPU.
  /// @returns               The user part of the IMPU
  std::string user_from_impu(std::string impu);

protected:
  const Config* _cfg;
  HTTPDigestAuthenticate* _auth_mod;
  void respond_when_authenticated();

  std::string _impu;
};

#endif
