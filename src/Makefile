TARGETS := memento
TEST_TARGETS := memento_test

COMMON_SOURCES := localstore.cpp \
                  memcachedstore.cpp \
                  memcachedstoreview.cpp \
                  memcached_config.cpp \
                  signalhandler.cpp \
                  logger.cpp \
                  saslogger.cpp \
                  statistic.cpp \
                  utils.cpp \
                  load_monitor.cpp \
                  log.cpp \
                  handlers.cpp \
                  httpstack.cpp \
                  httpstack_utils.cpp \
                  accesslogger.cpp \
                  authstore.cpp \
                  httpconnection.cpp \
                  homesteadconnection.cpp \
                  httpdigestauthenticate.cpp \
                  cassandra_store.cpp \
                  call_list_store.cpp \
                  call_list_xml.cpp \
                  dnsparser.cpp \
                  baseresolver.cpp \
                  dnscachedresolver.cpp \
                  httpresolver.cpp \
                  mementosaslogger.cpp \
                  call_list_store_processor.cpp \
                  mementoappserver.cpp \
                  base64.cpp \
                  unique.cpp \
                  alarm.cpp \
                  base_communication_monitor.cpp \
                  communicationmonitor.cpp \
                  zmq_lvc.cpp \
                  counter.cpp \
                  accumulator.cpp \
                  memento_lvc.cpp \
                  health_checker.cpp \
                  exception_handler.cpp \
                  namespace_hop.cpp \
                  httpnotifier.cpp \
                  astaire_resolver.cpp

memento_SOURCES := main.cpp ${COMMON_SOURCES}

memento_test_SOURCES := ${COMMON_SOURCES} \
                        test_main.cpp \
                        test_interposer.cpp \
                        sip_common.cpp \
                        handlers_test.cpp \
                        authstore_test.cpp \
                        call_list_store_test.cpp \
                        homesteadconnection_test.cpp \
                        httpdigestauthenticate_test.cpp \
                        call_list_store_processor_test.cpp \
                        mementoappserver_test.cpp \
                        fakelogger.cpp \
                        fakecurl.cpp \
                        fakehomesteadconnection.cpp \
                        faketransport_udp.cpp \
                        faketransport_tcp.cpp \
                        mock_sas.cpp \
                        httpnotifier_test.cpp \
                        mockhttpnotifier.cpp \
                        snmp_ip_count_table.cpp \
                        snmp_row.cpp

COMMON_CPPFLAGS := -I../include \
                   -I../usr/include \
                   -I../modules/cpp-common/include \
                   -I../modules/cpp-common/test_utils \
                   -I../modules/app-servers/include \
                   -I../modules/app-servers/test \
                   -I../modules/sas-client/include \
                   -I../modules/rapidjson/include \
                   `PKG_CONFIG_PATH=../usr/lib/pkgconfig pkg-config --cflags libpjproject` \
                   -fPIC

memento_CPPFLAGS := ${COMMON_CPPFLAGS}
memento_test_CPPFLAGS := ${COMMON_CPPFLAGS} -DGTEST_USE_OWN_TR1_TUPLE=0 -Wno-write-strings

# Add modules/cpp-common/src as a VPATH to pull in required common modules
VPATH := ../modules/cpp-common/src ../modules/cpp-common/test_utils ../modules/app-servers/test ut

COMMON_LDFLAGS += -lzmq \
                  -lssl \
                  -ldl \
                  -lcrypto \
                  -levhtp \
                  -levent_pthreads \
                  -lmemcached \
                  -levent \
                  -lsas \
                  -lz \
                  -lcurl \
                  -lpthread \
                  -lcares \
                  -lboost_regex \
                  -lboost_date_time \
                  -lthrift \
                  -lcassandra \
                  `net-snmp-config --netsnmp-agent-libs` \
                  `PKG_CONFIG_PATH=../usr/lib/pkgconfig pkg-config --libs libpjproject`

memento_LDFLAGS := ${COMMON_LDFLAGS}

# Test build also uses libcurl (to verify HttpStack operation)
memento_test_LDFLAGS := ${COMMON_LDFLAGS} -lcurl

include ../build-infra/cpp.mk

ROOT := ..
MODULE_DIR := ${ROOT}/modules
include ../modules/cpp-common/makefiles/alarm-utils.mk

../usr/include/memento_alarmdefinition.h : ../build/bin/alarm_header ../memento.root/usr/share/clearwater/infrastructure/alarms/memento_alarms.json
	$< -j "../memento.root/usr/share/clearwater/infrastructure/alarms/memento_alarms.json" -n "memento"
	mv memento_alarmdefinition.h $@

${memento_OBJECT_DIR}/main.o : ../usr/include/memento_alarmdefinition.h
