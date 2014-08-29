Memento Overview
================

Memento is an IMS application server. It uses the ISC interface for processing SIP call traffic and is invoked by Sprout in the normal fashion using iFCs.
Memento also exposes an HTTP(S) interface to UEs to allow them to download the call list for their subscriber.

SIP Interface
-------------

Memento acts as a SIP proxy. When it receives an initial INVITE it forwards the INVITE back to Sprout and record-routes itself into the dialog for the call.

Memento writes information about the call to persistent storage (supplied by a cassandra database) for later retrieval by the UE. These call fragments are written when a call begins, when a call ends, and when a call is rejected.

An example call list fragment (for a rejected call is):

```
<to>
  <URI>alice@example.com</URI>
  <name>Alice Adams</name>
</to>
<from>
  <URI>bob@example.com</URI>
  <name>Bob Barker</name>
</from>
<answered>0</answered>
<outgoing>1</outgoing>
<start-time>2002-05-30T09:30:10</start-time>
```

The contents of a call list entry are derived from the SIP signalling:

* The incoming/outgoing flag is derived from the session case on the initial INVITE.
* The answered/not-answered flag is inferred from the final response to the initial INVITE.
* The start time of the call is measured from the point the CLA receives the initial INVITE.
* The answer time of the call is measured from the point the CLA receives the 200 OK to the initial INVITE.
* The end time of the call is measured from the point the CLA receives the BYE.
* The caller's URI/name from the P-Asserted-Identity header for originating calls and the From header for terminating calls.
* The callee's URI/name from the To header for originating calls and the Request URI for terminating calls.

Any other mid-call messages are simply forwarded according to their route header (for a request) or via headers (for a response). If Memento receives an initial request other than an INVITE, it simply forwards the request back to the S-CSCF and does not record-route itself.

HTTP Interface
--------------

Memento exposes the following URL for retrieving call lists for a user:

    /org.projectclearwater.call-list/users/<IMPU>/call-list.xml

This supports GETs to retrieve an entire call list for a public user identity; all other methods return a 405.

Requests to this URL must be authenticated. Memento uses HTTP Digest authentication (RFC link), and supports the "auth" quality of protection. Memento uses the credentials provisioned in homestead for authenticating requests, in a similar way to how Sprout authenticates SIP REGISTERs. Memento also authorizes requests, ensuring that the authenticated IMPI is permitted to access the IMPU referred to in the URL of the request.

If the request has been authorized and authenticated Memento retrieves the call list fragments relating to the request IMPU from the call list store.
If there are entries, Memento will create an XML document containing complete calls and return this to the client

```
<call-list>
  <calls>
    <call>
      <to>
        <URI>alice@example.com</URI>
        <name>Alice Adams</name>
      </to>
      <from>
        <URI>bob@example.com</URI>
        <name>Bob Barker</name>
      </from>
      <answered>1</answered>
      <outgoing>1</outgoing>
      <start-time>2002-05-30T09:30:10</start-time>
      <answer-time>2002-05-30T09:30:20</answer-time>
      <end-time>2002-05-30T09:35:00</end-time>
    </call>
    <call>
      <to>
        <URI>alice@example.net</URI>
        <name>Alice Adams</name>
      </to>
      <from>
        <URI>bob@example.net</URI>
        <name>Bob Barker</name>
      </from>
      <answered>0</answered>
      <outgoing>1</outgoing>
      <start-time>2002-05-30T09:30:10</start-time>
    </call>
  </calls>
</call-list>
```

If there are no entries, Memento will respond with an empty call list, e.g.:

    <call-list><calls></calls></call-list>

Memento supports gzip compression of the call list document, and will compress it in the HTTP response if the requesting client indicates it is willing to accept gzip encoding.

Memento also uses Nginx to act as a SSL gateway.

Configuration
-------------

Memento is configured for a subscriber in their IFCs, and is registered as a general AS for INVITE requests.

An example IFC is:

```
<InitialFilterCriteria>
  <TriggerPoint>
  <ConditionTypeCNF>0</ConditionTypeCNF>
  <SPT>
    <ConditionNegated>0</ConditionNegated>
    <Group>0</Group>
    <Method>INVITE</Method>
    <Extension></Extension>
  </SPT>
  </TriggerPoint>
  <ApplicationServer><ServerName>sip:memento.cw-ngv.com</ServerName>
    <DefaultHandling>0</DefaultHandling>
  </ApplicationServer>
</InitialFilterCriteria>
```

There are also five deployment wide configuration options. These should be set in /etc/clearwater/config:

* `memento_enabled`: This determines whether the Memento application server is enabled. Set to 'Y' to enable it.
* `max_call_list_length`: This determines the maximum number of complete calls a subscriber can have in the call list store.
* `call_list_store_ttl`: This determines how long each entry should be kept in the call list store.
* `memento_threads`: This determines the number of threads dedicated to adding call list fragments to the call list store
* `memento_disk_limit`: This determines the maximum size that the call lists database may occupy.

Scalability
-----------

Memento is horizontally scalable. A cluster of Memento nodes provides access to the same
underlying Cassandra cluster and memcached cluster, allowing the load to be spread between nodes.
