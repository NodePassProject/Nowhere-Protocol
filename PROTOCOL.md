# Nowhere Protocol

NW3 is the current Wire version of Nowhere Protocol, providing authenticated
TCP and UDP forwarding over TLS 1.3 and QUIC, with Vector acting as the client
and Portal as the server.

| Protocol | Value |
| --- | --- |
| Name | Nowhere Protocol |
| Wire version | NW3 |
| ALPN | `nw3` |
| Transports | TLS 1.3 and QUIC |

## Contents

- [1. Overview](#1-overview)
- [2. Conventions](#2-conventions)
- [3. Roles and connections](#3-roles-and-connections)
- [4. Transport requirements](#4-transport-requirements)
- [5. Authentication](#5-authentication)
- [6. Connection establishment](#6-connection-establishment)
- [7. FlowStart and Target](#7-flowstart-and-target)
- [8. Setup results](#8-setup-results)
- [9. UDP flows](#9-udp-flows)
- [10. QUIC datagrams](#10-quic-datagrams)
- [11. Connection lifecycle](#11-connection-lifecycle)
- [12. Morph](#12-morph)

## 1. Overview

This specification defines the existing NW3 Core Wire contract for independent
implementations. It specifies connection authentication, Flow framing, TCP and
UDP delivery, and optional Morph. It does not prescribe a programming language,
process architecture, ingress interface, deployment configuration or exit policy.

This extraction does not introduce a protocol upgrade. There is no new version
field or capability negotiation. Fixed identifiers, including the ALPN and all
cryptographic labels, retain their exact existing bytes.

## 2. Conventions

A **connection** is one TLS or QUIC association. A **Flow** is one TCP byte stream
or one UDP association to a fixed **Target**. **Vector** is the protocol client
that initiates the connection and business Flows. **Portal** is the protocol
server that authenticates it and provides forwarding. These are protocol roles;
implementations do not need to use these names internally. Upload means
Vector-to-Target traffic; download is the reverse direction.

All multibyte integers are unsigned and use network byte order (big-endian).
Sizes are in bytes unless stated otherwise. `||` means byte concatenation;
`[0..16]` selects the first 16 bytes. `HMAC-SHA256(key, message)` identifies
the key and message arguments.
Quoted cryptographic labels are exact ASCII without a terminator. Frames
have no implicit padding, version byte or outer length field. A parser consumes
exactly the fields described for its current state. Diagrams are schematic;
field labels and tables specify byte sizes rather than drawing widths.

Uppercase MUST, MUST NOT, SHOULD and MAY express requirement levels as defined
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html). Wire layouts and state
transitions are binding; explicit implementation choices are not Wire constants.

## 3. Roles and connections

Arrows show connection establishment; traffic travels in both directions:

```text
                 TLS / QUIC                  Target connection
+----------+                   +----------+                   +----------+
|  Vector  |------------------>|  Portal  |------------------>|  Target  |
+----------+                   +----------+                   +----------+
```

Vector initiates Flows on one configured carrier. Portal authenticates the
connection and forwards to the requested Target. Each connection has exactly
one business Flow initiation direction. TLS uses one connection per Flow. Each
QUIC client-initiated bidirectional business Stream owns one TCP Flow or one
UDP control Flow. Target resolution and access belong to the selected exit;
its placement and forwarding implementation are outside this Core specification.

## 4. Transport requirements

Both transports use TLS 1.3 and only ALPN `nw3`. Peers reject missing or
other ALPN values. There is no negotiation or fallback. Normal clients verify
system CA trust and hostname, or an exact certificate SHA-256 pin. 0-RTT is
disabled, including on resumed connections. Authentication uses the normal
TLS exporter, never the early exporter.

## 5. Authentication

### 5.1 Shared Key

Shared Key is exactly 32 lowercase hexadecimal text characters. Its ASCII text
bytes enter the KDF directly; hexadecimal-looking text is not hex-decoded.
Provisioning is out of band. If a provisioning format percent-encodes the key,
decode it exactly once and reject malformed escapes before validating the key.
URL schemes and configuration field names are not part of the Wire format.

### 5.2 Vector key derivation

```text
salt       = SHA256("nowhere/nw3/auth-root")
root       = HMAC-SHA256(salt, shared_key)
vector_key = HMAC-SHA256(root, "vector-authentication" || 0x01)

exporter  = TLS-Exporter("EXPORTER-Nowhere-nw3-Auth", empty_context, 32)
tag       = HMAC-SHA256(vector_key, transport || exporter)[0..16]
transport = 0x01 (TLS), 0x02 (QUIC)
```

The root and Vector key each contain 32 bytes. `transport` is one byte, the
exporter context is empty, and its requested output length is 32 bytes. Labels
retain their exact spelling even in implementations with different role names.

### 5.3 AuthFrame

```text
+--------------------------------------------------------------+
|                        Tag: 16 bytes                         |
+--------------------------------------------------------------+
```

AuthFrame is exactly the 16-byte tag, with no role byte or metadata. Compare
tags in constant time. Invalid authentication closes the connection without a
SetupResult. A tag cannot move between connections, resumed connections or
transports. Successful authentication authorizes Vector Flows on that connection;
there is no separate authentication acknowledgement.

## 6. Connection establishment

| Connection | First request | Response |
| --- | --- | --- |
| Vector TLS | AuthFrame + FlowStart + Target | SetupResult |
| Vector QUIC | AuthFrame, optionally FlowStart + Target | See below |

For Vector QUIC, the first request uses client Stream 0. The response is
SetupResult if a Flow exists.

### 6.1 Vector establishment

The authentication Stream is client bidirectional Stream ID 0; accepting a
later Stream first does not authorize treating it as the authentication Stream.
Vector has no authentication ACK. The first Flow can be pipelined after Auth;
target payload waits for READY. EOF immediately after Vector QUIC Auth is an
authentication-only Stream: finish it normally without a SetupResult, Flow
permit or UDP route. Authentication remains connection-wide for later Streams.
Vector TLS requires a Flow because it is a dedicated connection.

TLS and a pipelined first QUIC Flow follow the same application ordering.
For QUIC, the request and result below use client bidirectional Stream 0:

```text
      Vector                                                  Portal
         |                                                       |
         |---------------- TLS / QUIC handshake ---------------->|
         |----------- AuthFrame + FlowStart + Target ----------->|
         |                  target payload waits                 |
         |<----------------- SetupResult: READY -----------------|
         |<============== TCP bytes / UDP packets ==============>|
         |                                                       |
```

A QUIC authentication-only Stream creates no Flow. Later Streams carry their
own FlowStart and Target without another AuthFrame:

```text
      Vector                                                  Portal
         |                                                       |
         |------------- Stream 0: AuthFrame + FIN -------------->|
         |<----------- Stream 0: FIN (no SetupResult) -----------|
         |------------ Stream 4: FlowStart + Target ------------>|
         |<--------------- Stream 4: SetupResult ----------------|
         |<=============== Flow data after READY ===============>|
         |                                                       |
```

### 6.2 Authentication resource limits

Handshake and authentication time, unauthenticated connection admission,
receive windows and Stream credit must be bounded. Only client bidirectional
Stream 0 carries authentication; unidirectional Streams have no NW3 messages.
DATAGRAMs are dropped until authentication completes. No target dial or unbounded
business allocation precedes authentication. After success, business Stream
admission remains bounded independently of available QUIC transport credit.
Exact timeouts, receive windows and admission counts are implementation policy.

## 7. FlowStart and Target

FlowStart is one byte. Bit 0 identifies the Flow type (0 = TCP, 1 = UDP).
Bits 1–7 are reserved for future use. Senders MUST set these bits to zero;
receivers MUST ignore them. Target immediately follows:

| ATYP | Address bytes | Final field |
| --- | --- | --- |
| `01` IPv4 | Four address bytes | Two-byte port |
| `03` Domain | One-byte length, then that many domain bytes | Two-byte port |
| `04` IPv6 | Sixteen address bytes | Two-byte port |

Target encodes the port in network byte order; port zero is invalid. IPv4 and
IPv6 use raw address octets, without text delimiters or IPv6 scope IDs. A domain
contains 1–253 ASCII bytes in IDNA wire form. Each dot-separated label contains
1–63 ASCII letters, digits or hyphens and cannot begin or end with a hyphen.
Empty labels and a trailing dot are invalid. Unicode names must be converted to
IDNA before encoding. DNS resolution belongs to the selected exit.

### 7.1 FlowStart byte

```text
+-----------------------------------+-------------+
|             Bits 7..1             |    Bit 0    |
| Reserved: send zero, ignore on RX | TCP=0 UDP=1 |
+-----------------------------------+-------------+
```

### 7.2 Target layouts

```text
IPv4
+-------------+----------------------------+-------------+
|  ATYP: 0x01 |       IPv4: 4 bytes        |   Port: 2   |
+-------------+----------------------------+-------------+

IPv6
+-------------+----------------------------+-------------+
|  ATYP: 0x04 |       IPv6: 16 bytes       |   Port: 2   |
+-------------+----------------------------+-------------+

Domain
+-------------+------------+----------------------------+-------------+
|  ATYP: 0x03 | Length: 1  |    Domain: length bytes    |   Port: 2   |
+-------------+------------+----------------------------+-------------+
```

There is no Target length prefix outside its address-type-specific encoding.
Invalid ATYP, invalid Target or truncated input fail only that Flow. TCP carries
reliable payload after READY and preserves half-close, per-Flow cancellation and
bounded local shutdown/read deadlines.

## 8. Setup results

SetupResult is exactly one byte:

| Value | Meaning |
| --- | --- |
| `0` | READY |
| `1` | INVALID_REQUEST |
| `2` | FLOW_LIMIT |
| `3` | DIAL_FAILED |
| `4` | INTERNAL_ERROR |

Resource exhaustion fails promptly with FLOW_LIMIT. Target setup failure gives
DIAL_FAILED. Each Flow sends at most one SetupResult; after READY, close/reset
ends it. Authentication and role-direction violations close the connection;
ordinary Flow errors leave other QUIC Flows intact.
Unknown SetupResult values are invalid and must not authorize payload.
No carrier fallback is permitted, including for missing DATAGRAM support.

```text
                    +-------------------------+
                    |    FlowStart + Target   |
                    +------------+------------+
                                 |
                    +------------v------------+
                    |       Target setup      |
                    +------------+------------+
                                 |
                +----------------+----------------+
                |                                 |
   +------------v------------+       +------------v------------+
   |    SetupResult: READY   |       |    SetupResult: error   |
   +------------+------------+       +------------+------------+
                |                                 |
   +------------v------------+       +------------v------------+
   |      Payload phase      |       |      End this Flow      |
   +------------+------------+       +-------------------------+
                |
   +------------v------------+
   |      Close or reset     |
   +-------------------------+
```

| Failure | Scope |
| --- | --- |
| Invalid authentication or business Stream initiator | Close the connection |
| Invalid Target or truncated request | End the affected Flow |
| Per-Flow resource/dial failure | End the affected Flow |
| Failure after READY | Close/reset the Flow; do not send a second SetupResult |

## 9. UDP flows

### 9.1 Stream-derived identity

For a QUIC UDP control Stream:

```text
flow_id = (quic_stream_id >> 2) + 1
```

The low two Stream ID bits encode direction; they are checked before derivation:

```text
+---------------------------+------------------+--------------------+
|      Stream sequence      |      Bit 1       |       Bit 0        |
|        raw ID >> 2        |  0=bidi, 1=uni   | 0=client, 1=server |
+---------------------------+------------------+--------------------+
```

Check the raw Stream's bidirectional bit and initiator first. Only
client-initiated business Streams are valid on a Core connection. Compute in a
wide integer, then require `1 <= flow_id <= 2^30 - 1` before converting.
Never truncate or wrap. The last usable raw client Stream ID is `4294967288`.
Authentication-only Stream 0 creates no UDP route; the next client Stream 4
derives ID 2. TCP needs no business ID.

IDs have meaning only within that QUIC connection. There is no cross-connection
map, allocator or retired-ID set. For exhaustion handling, see
[Connection lifecycle](#11-connection-lifecycle).

### 9.2 Control Stream and DATAGRAM lifetime

After READY, keep both directions of a UDP control Stream open; it carries no
business bytes. FIN, RESET, STOP_SENDING, idle timeout or connection loss
triggers idempotent route/task/permit/reassembly cleanup. CLOSE DATAGRAM is
an auxiliary signal; its loss cannot keep a terminated Flow alive. Nonempty
post-READY control data is invalid for that Flow. Unknown, unauthenticated or
not-yet-READY IDs are dropped without allocating routes or reassembly slots.

The reliable Stream owns lifecycle; DATAGRAM carries complete or fragmented
UDP payloads on the same QUIC connection:

```text
     Initiator                                               Acceptor
         |                                                       |
         |--------- Control Stream: FlowStart + Target --------->|
         |<--------------- Control Stream: READY ----------------|
         |      control Stream stays open; no payload bytes      |
         |<============= DATAGRAM: DATA / FRAGMENT =============>|
         |      FIN / RESET / STOP_SENDING / timeout / loss      |
         |         reclaim route, tasks and permits once         |
         |                                                       |
```

### 9.3 TLS UDP framing

TLS UDP uses a two-byte big-endian length followed by one complete payload
(UoT), repeated independently in each direction. The length excludes its own
two bytes and permits 0–65535 payload bytes. Zero length represents an empty
datagram, not closure. EOF between packets ends the Flow; EOF inside a length
or payload is truncation. The dedicated connection owns the Flow's lifetime.

```text
+-----------------+-------------------+-----------------+-------------------+
|   Length: u16   |  Payload: length  |   Length: u16   |  Payload: length  |
+-----------------+-------------------+-----------------+-------------------+
```

## 10. QUIC datagrams

### 10.1 Base word

The four-byte network-order base word has the following layout:

```text
+----------------------+------------------------------------------+
|  Type: bits 31..30   |           Flow ID: bits 29..0            |
| 0 DATA / 1 FRAGMENT  |              1 .. 2^30 - 1               |
| 2 CLOSE / 3 invalid  |            unsigned, nonzero             |
+----------------------+------------------------------------------+
```

DATA is the base word plus a complete business payload. CLOSE is exactly the
base word, with no trailing bytes. Empty DATA payloads are valid. Type `3`, zero
Flow IDs, truncated headers and oversized payloads are invalid and are dropped.
FRAGMENT adds an eight-byte fragment header after the base word:

| Bytes | Field |
| ---: | --- |
| 4 | Nonzero packet ID, network order |
| 1 | Zero-based fragment index |
| 1 | Fragment count, 2..255 |
| 2 | Total complete payload length, network order |

### 10.2 Packet layouts

```text
DATA
+----------------------+------------------------------------+
|  Base word: 4 bytes  |   Complete UDP payload: 0..65535   |
+----------------------+------------------------------------+

CLOSE
+----------------------+
|  Base word: 4 bytes  |
+----------------------+

FRAGMENT header (12 bytes), followed by nonempty fragment payload
+--------------+--------------+----------+----------+--------------+
| Base word: 4 | Packet ID: 4 | Index: 1 | Count: 1 | Total len: 2 |
+--------------+--------------+----------+----------+--------------+
```

### 10.3 Fragmentation and reassembly

The complete payload is at most 65535 bytes. Fragment payloads are nonempty,
`index < count`, and `total_len >= count`. A fragment must leave at least one
byte for every other fragment. Use DATA when the complete packet fits the peer's
DATAGRAM limit; otherwise split into at most 255 FRAGMENT frames. A sender that
cannot fit the header and a payload byte cannot send that packet.

Reassembly is scoped by connection, Flow ID and packet ID. All fragments of a
packet agree on count and total length. Deliver only after every index is present
and the concatenation in index order has exactly `total_len` bytes. Identical
duplicates do not add bytes; conflicting metadata or payload invalidates the
partial packet. Fragments may arrive out of order. Packet IDs are nonzero and
must distinguish concurrent partial packets within the same Flow.

For a three-fragment packet, arrival order does not change delivery order:

```text
Arrival                 Reassembly by index                  Delivery
+----------+            +----------+----------+----------+   +----------+
| 2, 0, 1  |----------->|    0     |    1     |    2     |-->|  packet  |
+----------+            +----------+----------+----------+   +----------+

Missing fragment        Keep a bounded partial packet until TTL/cleanup.
Conflicting fragment    Drop the partial packet; release its reservation.
Complete packet         Deliver once all indices and total length validate.
```

### 10.4 Resource bounds and forwarding

Reassembly and queued packets require bounded slot counts, byte reservations,
per-Flow queues and partial-packet lifetimes. Admission is nonblocking; a slow
Flow must not block the connection dispatcher. Empty packets consume a budget
unit. Reservations survive until packet/fragment delivery or cleanup. Numerical
budgets, eviction policy and timeout values are local implementation choices.

When forwarding across connections, bridge complete business datagrams. Each
side reassembles and encodes/fragments independently with its own connection-local
ID and MTU. IDs have no cross-connection meaning.

## 11. Connection lifecycle

A connection owns its authentication state, active Flows, UDP routes and
reassembly state. Connection loss ends every dependent Flow. Reconnect starts
new Flows only; it does not resume a prior Flow or transfer its identity.
Flow termination reclaims its resources once, independently of unreliable
CLOSE delivery. Per-Flow cancellation does not terminate unrelated QUIC Flows.

At derived-ID exhaustion, stop admitting new Flows, drain for a bounded local
deadline, close and reconnect. There is no exhaustion control frame. QUIC
keepalive and idle timeouts maintain liveness without an application heartbeat.
The specification does not assign portable QUIC application error codes or
close-reason strings; use the failure scopes above, not implementation diagnostics.

## 12. Morph

Morph is an optional transform below TLS/QUIC. Peers must agree out of band
on Shared Key and whether Morph is enabled; no in-band switch or detection
is performed. With Morph disabled, the transport bytes pass through unchanged.

### 12.1 Key derivation

Use the same Shared Key bytes as authentication:

```text
root    = HMAC-SHA256("nowhere/nw3/morph", shared_key)
tcp_c2s = HMAC-SHA256(root, "tcp c2s" || 0x01)
tcp_s2c = HMAC-SHA256(root, "tcp s2c" || 0x01)
udp_c2s = HMAC-SHA256(root, "udp c2s" || 0x01)
udp_s2c = HMAC-SHA256(root, "udp s2c" || 0x01)
```

Each output is a 32-byte key. The Morph root label is used directly as the HMAC
key; unlike authentication, it is not hashed first. The Morph root domain provides
domain isolation. Directions follow transport roles: Vector sends with the `c2s`
key and Portal sends with the `s2c` key for the selected carrier.

### 12.2 TCP encapsulation

```text
Client to server
+-------------+-----------+-----------------------------+
| Prelude: 64 | Nonce: 12 |   ChaCha20-XOR(TLS bytes)   |
+-------------+-----------+-----------------------------+

Server to client
+-----------------------------+
|   ChaCha20-XOR(TLS bytes)   |
+-----------------------------+
```

The client sends a 64-byte random prelude and a 12-byte random nonce before the
masked TLS stream. These 76 bytes are not encrypted by Morph. The server consumes
them without interpreting the prelude and sends no bootstrap of its own.
Prelude byte distribution is sender policy, not a field to negotiate or decode.
Receivers consume exactly 64 bytes and must not reject a prelude because its
bytes do not match a particular distribution. Prelude and nonce generation
use a secure random source.

Each direction uses IETF ChaCha20 with its directional key, the client's nonce
and initial block counter zero. Cipher positions advance continuously across
reads, writes and TLS records, independently by direction. Partial writes advance
only by bytes actually written. Exhaustion fails the stream before keystream
reuse; an implementation may impose an earlier bound. Never wrap the IETF
ChaCha20 32-bit block counter.

### 12.3 UDP encapsulation

```text
+-------------------+-------------------------------------------+
|     nonce: 12     |    ChaCha20-XOR(one QUIC UDP datagram)    |
+-------------------+-------------------------------------------+
```

Each outgoing UDP datagram receives a fresh unpredictable 12-byte nonce. Apply
IETF ChaCha20 with the sending direction's key and block counter zero, then prefix
the nonce. The receiver removes the nonce and applies the corresponding key.
The 12-byte prefix is outside the QUIC packet and must be included in path-MTU
accounting. Packets no longer than the nonce are discarded.

A segmented send applies an independent nonce and transform to every UDP segment.
A coalesced receive removes each segment's nonce separately and adjusts lengths
and stride before handing datagrams to QUIC. UDP boundaries must be preserved;
a nonce is never shared across a GSO batch as if it were one datagram.

Morph provides wire masking, not authentication or integrity. TLS/QUIC still
provides authenticated encryption, certificate validation and replay protection.
