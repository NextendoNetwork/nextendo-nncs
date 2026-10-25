# Native NAT filtering probe

The observed production responders answer message 102 from the same socket that
received it. The documented protocol requires message 102 to reply from the
same address but the other NNCS port. A response from the solicited endpoint
cannot reveal address-and-port-dependent filtering, and can make a restrictive
network appear more open to the console's classifier.

This change binds 10025 and 10125 once, shares both sockets between receive loops,
and sends message 102 through the other socket. Messages 101 and 103 retain their
original reply socket. Observed client IPv4/port, message ID, server-address word,
endpoint bridge files and sinkhole behavior are preserved. The program does not
return a NAT letter or manufacture different letters for different users.

Tests use real local UDP sockets in both directions and simulated acceptance
rules: an open filter accepts the alternate-port response; an endpoint-dependent
filter rejects it while accepting normal replies. Client-supplied address words
are ignored. This verifies packet semantics, not physical NAT A/B/C/D/F acceptance.

Before deployment, reconcile the running binary/configuration with this source,
retain each node's public-address configuration and endpoint data volume, prepare
rollback, and test both public nodes. Obtain administrator approval before any
restart. Final acceptance needs consoles on networks with independently known
different NAT behavior. An HTTP connection-test success is not that evidence.

Scope: the native/Pia 101/102/103 flow. This patch does not claim to implement the
separate NEX 1–5 protocol fully: its type 2 requires a response from another IP,
and type 3 also requires another port. Those existing gaps require separate
coordination across nodes; do not claim complete NEX NAT compliance from this fix.

Protocol reference: https://github.com/kinnay/NintendoClients/wiki/NAT-Check-Server
