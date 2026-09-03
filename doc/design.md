# nymserv-ng — Design, Threat Model and Audit of the Proposed Go Implementation

Target deployment: `nym.virebent.art`
Interoperability requirement: current YAMN network (`github.com/crooks/yamn`)
Security tier: §2.1 baseline + §2.2 mixnet/anonymity tier

---

## 0. Executive finding

The submitted `nymserver.go` is a Go port of the **nym.alias.net / Mazières nymserv**
architecture (`.rb` / `.nrb` reply blocks, `confirm<cookie>@host` activation, `finger`
daemon, `FL_*` flag word, `MSGPERDAY`, `saferename`, `wipe`).

That architecture **cannot be made compatible with YAMN**, because it depends on
Type I (Cypherpunk) anonymous reply blocks, and **YAMN has no reply-block packet
type at all**.

From the YAMN packet specification (mixmin.net), the Sealed Header carries:

```
Packet Type ID   1 byte   Intermediate Hops = 0, Exit Hop = 1
Delivery Method  1 byte   0 = SMTP, 255 = Dummy
```

There is no third packet type, no SURB, no reply-block construction, and the Exit
Hop packet info contains no return path. YAMN is a strictly forward-only Type II
mix network:

```
Headers   2560 bytes   10 x 256 (one per hop, max chain length 10)
Body     17920 bytes
Total    20480 bytes
Crypto:  NaCl Box (X25519/XSalsa20-Poly1305) + AES-256-CTR + Blake2
Pooling: binomial mix
```

Consequently every reply-block code path in the submitted file
(`runConfirm`, `.rb`/`.nrb` handling, the `Reply-Block:` config header, the
confirmation cookie flow) is dead weight against the stated requirement.

**The only nym delivery model that is compatible with the live YAMN network is
the Zax model**: messages *from* the nym go out over YAMN as ordinary forward
messages; messages *to* the nym are encrypted and published to a **shared
mailbox** that the nym owner polls. Zax's `crooks/nymserv` uses
`alt.anonymous.messages` with hSub subject tags for exactly this reason.

This is not a downgrade. Against a global passive adversary, a polled shared
mailbox is **strictly stronger** than a reply block:

| Property | Reply block (nym.alias.net) | Shared mailbox (Zax model) |
|---|---|---|
| Return path secret | Stored server-side, static | Does not exist |
| Server seizure | Reveals full return route | Reveals nothing about recipients |
| Recipient anonymity set | 1 (the reply block owner) | All readers of the mailbox |
| Delivery correlation | Inbound mail → outbound mix packet, 1:1 | Broken by pooling + dummies |
| Forward secrecy | None (static route + static key) | Achievable via one-time prekeys |
| Works on YAMN | **No** | **Yes** |

**Recommendation: abandon the reply-block design entirely. Rebuild on the Zax
delivery model with modern primitives, forward secrecy and a proper mix pool on
the outbound side.**

---

## 1. Audit of the submitted implementation

### 1.1 Blocking defects (the program cannot function)

#### Vulnerability: argument parsing aborts before any command runs
**Target**: `main()`
**Severity**: Critical (functional)
**Attack class**: n/a — logic error
**Attack steps**: `flag.Parse()` is called with no flags registered. When
`os.Args[1]` is `-d`, the standard library prints `flag provided but not
defined: -d` and calls `os.Exit(2)`. `flag.Args()` is never reached with the
intended content.
**Impact**: Every invocation mode (`-d`, `-fingerd`, `-wipe`, `-expire`) is
unreachable.
**Mitigation**: Use a subcommand dispatch on `os.Args[1]` before `flag.Parse()`,
or register real flags.

#### Vulnerability: `decryptStdin()` performs no decryption and writes the wrong path
**Target**: `decryptStdin`, `runConfig`, `runSend`
**Severity**: Critical (functional + confidentiality)
**Attack steps**: The function scans stdin for `-----BEGIN YAMN MESSAGE-----`
and copies the armor verbatim to `QPREF + ".i"`. Both callers then read
`QPREF + ".m"`, which is never created, and abort with `fatal(66, ...)`.
Additionally, no decryption of any kind is attempted — `encryptMessage` and
`decryptMessage` are defined and **never called anywhere in the file**.
**Impact**: The config and send paths are non-functional. Had they worked, they
would have processed attacker-supplied plaintext as if it had been
authenticated.
**Mitigation**: See §3.2 — the inbound envelope must be a real AEAD open with
sender authentication, not an armor scan. Note also that
`-----BEGIN YAMN MESSAGE-----` is the wire format *between remailers*; a message
that has already exited the mix and been delivered to your MTA no longer carries
it.

#### Vulnerability: replay and confirmation state is per-process memory
**Target**: `replayCache`, `confirmCache`, `generateCookie`, `runConfirm`
**Severity**: Critical
**Attack class**: Replay
**Prerequisites**: Ability to resend a captured message to the MTA.
**Attack steps**:
1. The binary is a **per-message local delivery agent** (`nymserv -d recipient`),
   spawned by the MTA and terminated after each message.
2. `replayCache` and `confirmCache` are `map[...]` globals. They are populated
   and then discarded at `os.Exit`.
3. Resend any captured `send@` message. The replay cache is empty in the new
   process; the message is accepted again.
4. `runConfig` generates a cookie into `confirmCache` and exits. `runConfirm` in
   a later process finds an empty map and calls `leave(0)`.
**Impact**: Zero replay protection. The confirmation flow can never succeed —
no alias can ever be activated.
**Mitigation**: Persistent state in a long-running daemon (§2).

#### Vulnerability: `parseLegacyPublicKey` cannot parse OpenPGP
**Target**: `parseLegacyPublicKey`, `processPublicKeyBlock`
**Severity**: High (functional)
**Attack steps**: The function strips the armor delimiters, joins the remaining
lines and base64-decodes them, expecting exactly 32 bytes. An OpenPGP armored
block's base64 body is a **packet stream** (public-key packet, user IDs,
signatures, subkeys) followed by a `=`-prefixed CRC24 checksum line. It is never
32 bytes, and the CRC line will usually break `StdEncoding.DecodeString`
outright.
**Impact**: Every legacy Zax-format config request is rejected. Backward
compatibility is illusory.
**Mitigation**: If OpenPGP compatibility is wanted, parse it with
`github.com/ProtonMail/go-crypto/openpgp` and extract a real Ed25519/Curve25519
subkey. Otherwise drop the code path and say so in the nym server help text.

#### Vulnerability: YAMN is invoked with Mixmaster syntax, and never invoked at all
**Target**: `REMAIL`
**Severity**: High (functional)
**Attack steps**: `REMAIL = HOMEDIR + "/yamn/yamn -SR"`. `-S`/`-R` are Mixmaster
2.x flags. YAMN's client interface is `yamn --mail <file>`, optionally with
`--chain` and `--copies`. The variable is in any case never referenced by any
function in the file — nothing is ever submitted to the mix network.
**Mitigation**: §3.3.

---

### 1.2 Metadata and anonymity defects

#### Vulnerability: Message-ID leaks nanosecond timestamp and PID
**Target**: `rcvdLine`
**Severity**: High
**Attack class**: Traffic correlation / metadata leakage
**Attack steps**: `fmt.Sprintf("<%d.%d@%s>", time.Now().UnixNano(), os.Getpid(), HOSTNAME)`
embeds the exact arrival instant at nanosecond resolution plus the delivery
agent PID in a header that travels with the message. A passive observer holding
one delivered message can pin the arrival time at the nymserver to the
nanosecond and correlate it against inbound SMTP flow captured at the host.
The PID additionally discloses process-spawn ordering, i.e. relative message
volume.
**Mitigation**: `Message-ID: <base32(16 random bytes)@invalid>`. Never derive
identifiers from time or process state.

#### Vulnerability: `Received:` header preserves per-nym arrival metadata
**Target**: `rcvdLine`, `msgFile`, `runReceive`
**Severity**: High
**Attack steps**: The generated header contains `with unique id <msgid> for
<user+extra@host>` and an RFC1123Z timestamp, and is prepended to the message
delivered to the nym.
**Impact**: Any later disclosure of a single message (compelled or otherwise)
reveals alias, arrival time and a correlatable unique id.
**Mitigation**: Strip *all* trace headers. The nym owner needs the message body
and a minimal header set (`From`, `To`, `Subject`, `Date` coarsened to the hour);
nothing else.

#### Vulnerability: error paths write user identifiers into MTA logs
**Target**: `fatal`, all call sites
**Severity**: High
**Attack class**: Persistent metadata retention
**Attack steps**: `fatal` writes to `os.Stderr`. A local delivery agent's stderr
is captured by Postfix and written to `/var/log/mail.log` with a timestamp. Call
sites pass alias names, error strings and header content — e.g.
`fatal(0, errStr)` in `runConfig` after `errStr` has accumulated
`Unknown header: %s` lines containing raw attacker/user input.
**Impact**: Direct violation of the zero-persistent-metadata mandate. A host
seizure yields a timestamped list of which aliases received mail and when.
**Mitigation**: Exit codes only. No stderr output in production builds. Log to
`/dev/null` or to an in-memory ring buffer that is never flushed to disk.
Configure Postfix to discard LDA stderr.

#### Vulnerability: immediate response creates a 1:1 timing correlation
**Target**: `runConfig`, `runConfirm`, `runReceive`, `bumpMsgCount`
**Severity**: High
**Attack class**: Timing correlation, global passive adversary
**Attack steps**: Every one of these paths calls `sendToUser` synchronously in
the same process that consumed the inbound message. Inbound SMTP connection at
T and outbound at T+ε with ε in the millisecond range is a perfect linkage for
an observer with visibility on both sides of the host.
**Impact**: Defeats the purpose of the whole system. YAMN's binomial mix is
bypassed entirely for the world→nym direction, which never enters the mix.
**Mitigation**: §4 — mandatory pooling with a binomial or Poisson release
schedule, plus dummy output.

---

### 1.3 Correctness and privilege defects

#### Vulnerability: `readUserDat` fails open for unknown aliases
**Target**: `readUserDat`
**Severity**: Medium
**Attack steps**: When `ioutil.ReadFile` fails (file absent, permission error,
I/O error) the function returns `(today, 0, today, DEFFLAGS, "", nil)` — a
**nil error** and default enabled flags. `runReceive` calls it and checks only
`flags&FL_DISABLED`, which is clear in `DEFFLAGS` (`0xfd`).
**Impact**: An unknown or deliberately disabled alias whose `.dat` file was
removed is treated as enabled. Partially masked by the `.pgp` existence check in
`runDeliver`, but the invariant is wrong and the mask is incidental.
**Mitigation**: Distinguish `os.ErrNotExist` from every other error. Fail closed.

#### Vulnerability: flock file is unlinked while held
**Target**: `unlockUser`
**Severity**: Medium
**Attack class**: Race condition
**Attack steps**:
1. Process A opens `<user>.lock`, acquires `LOCK_EX`.
2. Process A finishes and calls `os.Remove` on the path, then closes.
3. Process B had already opened the same path and is blocked on `flock`. It now
   holds a lock on an **unlinked inode**.
4. Process C opens the path, which no longer exists, creates a **new** inode and
   acquires `LOCK_EX` on it immediately.
5. B and C both believe they hold the user lock and both call `writeUserDat`.
**Impact**: Corrupted counters, lost flag updates, daily-limit bypass.
**Mitigation**: Never unlink flock files. Create them once at provisioning time
and leave them. Also: `lockUser` never closes `f`, leaking a descriptor, and the
`currentUserLockCount` recursion counter is process-local and therefore
meaningless in a per-message process.

#### Vulnerability: `.forward` files are executed through `sh -c`
**Target**: `runDeliver`
**Severity**: Critical if any write path to `NDIR` exists
**Attack class**: Command injection / arbitrary code execution
**Attack steps**: If `<recipient>.forward` begins with `|`, the remainder is
passed to `exec.Command("sh", "-c", cmdStr)` with stdin, stdout and stderr wired
to the delivery agent's. Any primitive that lets a user influence the content or
creation of a file in `NDIR` becomes RCE as the nymserv user.
**Impact**: Full compromise of the nym database, all private keys, all queued
messages.
**Mitigation**: Remove the feature. A nym server has no legitimate need to pipe
mail to shell commands. If aliasing to a local address is required, do it in the
MTA's own alias map, not in a user-writable directory.

#### Vulnerability: TOCTOU on the daily message counter
**Target**: `bumpMsgCount`
**Severity**: Low
**Attack steps**: `writeUserDat` acquires and releases the lock, then
`bumpMsgCount` calls `readUserDat` **outside** the lock and decides on
`FL_DISABLED` from that stale read. Concurrent deliveries interleave and the
`MSGPERDAY` ceiling is exceeded.
**Mitigation**: Read-modify-write inside a single critical section, or move
counters into the daemon's transactional store.

#### Other defects, briefly

| Location | Issue |
|---|---|
| `runConfig` | `if len(line) > MAXLINES` compares a line *length* against a line *count*. Header line count is never bounded. |
| `runReceive` | Reads stdin without any size cap despite `MSGSIZE`/`MSGSZUNIT` being declared. Trivial disk-fill DoS. |
| `generateCookie` | `rand.Read(b)` error ignored. On failure `b` stays all-zero and the cookie is `+0000000000000000`. Also writes to `confirmCache` without holding `confirmMutex` in one of two call paths. |
| `generateCookie` | Stores `cookie→user` and `user→cookie` in the **same** map, so the key spaces collide. |
| `runConfirm` | Acquires `confirmMutex`, then `leave(0)` → `os.Exit` on the success path with the mutex held; on the `!ok` path it exits while holding it too. |
| `sendToUser` | `dontSign` and `newRB` parameters are accepted and never used. Callers believe they are controlling signing behaviour; they are not. |
| `wipeFile` | Overwriting in place is a no-op for secure deletion on ext4 with journaling, on any SSD with wear levelling, and on any CoW filesystem. It provides false assurance. |
| `loadPassphrase` | The passphrase is read, wrapped in memguard, frozen — and never used by any function. memguard theatre. |
| `saferename` | `os.Link(newPath, tempPath)` links the *destination* before the rename; if the destination does not yet exist this always fails and the function silently degrades to a bare rename. |
| `runReceive` | `defer f.Close()` plus an explicit `f.Close()` → double close. |
| `tmpFile` | Writes message content with mode `0644` into `QDIR`. |
| everywhere | `ioutil` (deprecated since Go 1.16), raw `syscall` instead of `golang.org/x/sys/unix`, no `context`, no timeouts on `exec.Command`. |
| `runSend` | If no `From:` is found, `sender` is `""` and sendmail is invoked as `-f ""`. |
| `runSend`, forward path, `runReceive` | No `X-Loop` header inserted. Only `replyHdr` checks for one. Mail loops are reachable. |

---

## 2. Proposed architecture

### 2.1 Process split

The single fatal structural mistake of the submitted design is that it is a
**per-message process with in-memory state**. Nothing that matters — replay
caches, mix pools, ratchet state, rate limits — can live there.

```
                 ┌──────────────────────────────────────────┐
   Postfix ──────▶ nym-lda   (per message, ~200 LOC)         │
   (LDA pipe)    │  - reads stdin, hard size cap             │
                 │  - AF_UNIX SOCK_SEQPACKET to nymd         │
                 │  - no state, no crypto, no logging        │
                 └──────────────┬───────────────────────────┘
                                │ /run/nymserv/ingest.sock (0600)
                 ┌──────────────▼───────────────────────────┐
                 │ nymd    (long-running, user `nymserv`)   │
                 │  - envelope open + sender auth           │
                 │  - persistent replay cache (BLAKE2b+TTL) │
                 │  - nym registry, prekey pools            │
                 │  - OUTBOUND MIX POOL (binomial)          │
                 │  - dummy traffic generator               │
                 └───────┬──────────────────────┬───────────┘
                         │                      │
              nym → world│                      │world → nym
                         ▼                      ▼
                 yamn --mail            NNTP POST (shared mailbox)
                 (forward-only mix)     news.tcpreset.net + a.a.m
                                        ▲
                                        │ polled over Tor onion NNTP
                                        └── nym owner's client
```

`nymd` runs as a dedicated non-privileged system user, no shell, no login. It
never needs root. It binds a unix socket, not a TCP port.

### 2.2 Why the shared mailbox and not SMTP delivery

The world→nym direction never enters YAMN (YAMN cannot carry it). If `nymd`
sends SMTP directly to a recipient, the recipient address is the anonymity
failure. Publishing to a shared mailbox that many people read moves the
anonymity set from 1 to |readers|, and the retrieval is done by the nym owner
over Tor, out of band.

**DECIDED: `alt.anonymous.messages` only.** A group hosted solely on
`news.tcpreset.net` was considered and rejected: it would shrink the anonymity
set to "people who connect to your INN2 to read that group", and connecting
would itself classify a reader as interested in the nymserver. On a.a.m the
reader never touches your infrastructure and can fetch from any provider.

**DECIDED: `nymd` does not inject via NNTP.** It sends the post to a mail2news
gateway *through YAMN*. The injection path is anonymised by the mix itself, and
`news.tcpreset.net` stays out of the picture entirely — otherwise the `Path`
header of every nym message would publicly identify you as the operator.

Selective retrieval uses **hSub**-style tags: a keyed hash over a per-message
nonce, computed with the nym's subject key, ratcheted forward after every use
(§3.6). The owner recomputes the tags for a forward window and only
trial-decrypts on a match. Tags are fixed-length and never repeat.

### 2.3 Registry persistence — sealed on disk, unsealed manually

**DECIDED: encrypted on disk, sealing key held off-host, manual unseal after
every restart. No re-registration.**

- The registry (alias → identity public key, ratchet state, prekey pool, flags,
  counters) is stored as a single sealed blob:
  `XChaCha20-Poly1305(K_seal, nonce, registry)`, rewritten atomically on change.
- `K_seal` is derived from a passphrase you supply at unseal time via
  Argon2id, or is supplied directly as 32 bytes. It is **never** written to the
  host — not in a file, not in an environment variable, not in a systemd
  credential on disk.
- On start, `nymd` runs sealed: the ingest socket accepts and pools messages it
  cannot yet process, and processes nothing. It unseals when you connect to
  `/run/nymserv/control.sock` over SSH-through-onion and provide the key.
- `K_seal` lives in RAM in a `memguard.LockedBuffer` for the process lifetime.
  This is the one place memguard actually earns its keep — unlike the submitted
  code, where the frozen passphrase buffer is never read by anything.
- Swap is disabled host-wide (§6). Without that, sealing is theatre.

A powered-off seizure yields ciphertext. A live seizure yields the registry;
that residual is documented in §5.3 and is bounded by the hSub ratchet (§3.5).

### 2.4 Server key hierarchy

The envelope in §3.2 encrypts to a server X25519 key. Nothing so far said where
clients get it, how they know it is authentic, or what happens when it rotates
— and a rotation that clients do not learn about in advance turns every
in-flight message into ciphertext nobody can open. Three keys, three lifetimes:

| Key | Type | Lifetime | Where the private half lives |
|---|---|---|---|
| Identity | Ed25519 | Permanent | **Off-host.** Signs key bundles offline; never on the VPS |
| Encryption | X25519 | 90 days | In the sealed registry, current + previous |
| Ratchet/session | X25519 | Per message | Ephemeral, discarded |

The identity key never touches the server. Signing a new bundle is a manual
offline operation, which is the point: compromise of the running host lets an
attacker read mail, but not impersonate the server to clients.

**Key bundle**, signed by the identity key:

```
magic        8   "NYMSNGK1"
valid_from   4   day number, big-endian
valid_until  4   day number, big-endian
enc_pk      32   X25519 public key for this epoch
prev_pk     32   previous epoch's key, or 32 zero bytes
sig         64   Ed25519 over all of the above
```

**Rotation with overlap.** A new bundle is published 30 days before the current
key expires. `nymservd` accepts envelopes to either key for the whole overlap;
clients switch as soon as they see a valid bundle. A client that has been
offline for more than 120 days must refetch before sending, and the client
refuses to send with an expired bundle rather than emitting undecryptable
ciphertext.

**Publication**, all three, so no single channel is a chokepoint:

1. Onion HTTPS service, the primary fetch path for `nymclient`
2. Posted to a.a.m on a fixed schedule under a well-known hSub tag derived from
   the identity key, so a client that can read the mailbox can always recover
   the current bundle
3. Identity key fingerprint on the clearnet page, for out-of-band verification

Clients pin the identity key on first use and refuse any bundle signed by a
different one. Changing the identity key is therefore a deliberate,
out-of-band event, announced and verified by fingerprint — not something a
compromised host can do quietly.

The `key_id` field in the envelope (§3.2) is `BLAKE2b-256(enc_pk)[:8]`, so
`nymservd` knows which private key to try without a trial decryption against
each.

---

## 3. Protocol

### 3.1 Primitives

Per project rules — no NIST curves, no NIST ciphers.

| Purpose | Primitive |
|---|---|
| Identity / signatures | Ed25519 |
| Key agreement | X25519 |
| AEAD | XChaCha20-Poly1305 |
| Hash / KDF | BLAKE2b (BLAKE2b-256 tags, BLAKE2b-512 KDF) |
| Constant-time compare | `subtle.ConstantTimeCompare` / `sodium_memcmp` equivalent |
| Randomness | `crypto/rand` only, **errors always checked** |

Note the layering: **YAMN's own crypto is not yours to change.** YAMN uses
NaCl Box + AES-256-CTR + Blake2 and you must speak it as-is to remain on the
network. AES-256-CTR appears only inside YAMN's packet format, below your
application layer. Your envelope sits *inside* the YAMN body and uses the table
above.

**Scoped exception for legacy mode.** Supporting existing Zax nymserv users
(§3.7) means accepting OpenPGP, and OpenPGP as deployed by GnuPG 2.2 offers
neither ChaCha20-Poly1305 nor BLAKE2. Legacy-mode messages will therefore use
RSA-2048+ or Ed25519/X25519 for the asymmetric layer and AES-256 for the
symmetric layer. This is a deliberate, documented departure from §2.1, scoped
to one code path, one registry flag and one deprecation window. It does not
propagate: modern-mode nyms never touch it, and no legacy primitive is
permitted anywhere outside the OpenPGP parser. NIST curves (P-256/384/521),
Brainpool, secp256k1, DSA and ElGamal are rejected in legacy mode too — the
exception is for RSA and AES, not for "whatever OpenPGP happens to offer".

### 3.2 Inbound envelope (nym owner → nymd)

Carried inside a YAMN message body, delivered by the mix to
`send@nym.virebent.art` or `config@nym.virebent.art`.

```
magic        8   "NYMSNG\x01\x00"
key_id       8   BLAKE2b-256(server enc_pk)[:8] — selects current or previous key
epk         32   X25519 ephemeral public key
nonce       24   XChaCha20-Poly1305 nonce (random)
ciphertext   n   AEAD(key, nonce, plaintext, ad = magic || key_id || epk)
tag         16
```

`key = BLAKE2b-256(X25519(esk, server_enc_pk) || epk || server_enc_pk)`

The plaintext is:

```
nym_pk      32   Ed25519 public key of the claiming nym
counter      8   strictly monotonic, big-endian, per nym
body_len     4   big-endian
body         n   RFC822 message or Config: block
sig         64   Ed25519(nym_sk, magic || key_id || epk || counter || body)
```

Rules enforced by `nymd`, in this order, all failures indistinguishable:

1. Total size within the accepted bucket set; reject otherwise.
2. AEAD open; on failure, consume a constant-time dummy path and drop.
3. Look up `nym_pk`; unknown key → drop silently (no bounce, ever).
4. `counter` strictly greater than the stored counter → else drop (replay).
5. `BLAKE2b-256(epk || nonce)` not in the replay store → else drop. Insert with
   TTL of 30 days.
6. Ed25519 verify. Failure → drop.
7. Only now does the message enter the pool.

A bounce, an error reply or a differential timing on any of these steps is an
oracle. There are no error replies. Diagnostics for the nym owner, if any, are
delivered through the same pooled shared-mailbox channel as ordinary mail, with
the same delay distribution.

### 3.3 Submission to YAMN

```
[nymserv]  /opt/nymserv/bin/yamn --mail --chain="*,*,*" /var/lib/nymserv/spool/out/<id>
```

Notes:

- Chain length 3 of a maximum 10. Longer chains cost latency and reliability;
  3 is the standard compromise. Do not pin named remailers — `*` draws from
  stats and preserves your own unpredictability.
- YAMN body capacity is 17920 bytes per packet; longer messages are chunked by
  YAMN itself and reassembled at the exit. Chunking is visible to the exit
  remailer as `Chunk num` / `Total number of chunks`, so **message size is
  disclosed at chunk granularity**. Pad to a whole number of chunks (§4.3).
- YAMN supports `Delivery Method 255 = Dummy`. Use it for cover traffic on the
  nym→world side rather than inventing your own.
- The spool file is written, `yamn --mail` is invoked, then the spool file is
  unlinked. Because in-place overwrite is not reliable secure deletion, the
  spool must live on **tmpfs** with swap disabled, not on the root filesystem.

### 3.4 Outbound to the shared mailbox (nymd → nym owner)

`nymd` produces a mail2news submission, hands it to `yamn --mail`, and the
gateway injects it into Usenet. `nymd` speaks no NNTP.

```
To: mail2news@<gateway>
Subject: <hsub tag, 48 hex chars>

Newsgroups: alt.anonymous.messages
From: Anonymous <nobody@invalid>
Subject: <same hsub tag>

<base64 of:>
  magic        8   "NYMSNG\x01\x01"
  epoch        4   hsub ratchet index, big-endian
  hsub_nonce  24   nonce used to derive the Subject tag
  prekey_id    8   which one-time prekey was consumed (0 = medium-term)
  epk         32   X25519 ephemeral public key
  nonce       24
  ciphertext   n   AEAD over the padded bucket
  tag         16
```

No `Date`, no `Message-ID`, no `Path`, no `Injection-Info`, no `User-Agent`,
no `X-Mailer`: the gateway supplies what Usenet requires, and every header
`nymd` omits is a header it cannot leak. Anything the gateway adds is added
identically for all of its users, which is the point of using one.

Two consequences to accept:

- The mail2news gateway sees the ciphertext and the hsub tag. It learns nothing
  about which nym the message is for, but it can count posts. Use more than one
  gateway, selected at random per message.
- Delivery reliability is now the product of YAMN's and the gateway's. Budget
  for loss; the client must tolerate gaps in the ratchet window (§3.6), which
  it does by design.

### 3.5 hSub tag derivation

```
tag_n     = BLAKE2b-256(K_n, nonce_n)   truncated to 24 bytes, hex → 48 chars
K_{n+1}   = BLAKE2b-256(K_n || "nymserv-ng/hsub-ratchet/v1")
```

48 hex characters to blend with the existing eSub/hSub convention on a.a.m.
`nonce_n` is 24 random bytes, carried in the payload so the owner can verify
the tag it matched.

`nymd` **erases `K_n` immediately after use** and stores only `K_{n+1}` and the
epoch index. Seizure at time T therefore cannot compute any tag issued before
T, which means it cannot identify a nym's past posts in a.a.m. This is what
makes the on-disk registry acceptable (§2.3); without it, the subject key would
be a permanent retroactive de-anonymisation key for every message ever sent.

The client keeps a forward window of 64 tags and matches against all of them,
so lost or reordered posts do not desynchronise it. On a match at index n+k it
advances its own ratchet by k+1.

### 3.6 Forward secrecy via one-time prekeys

The classic nymserver weakness is that seizing the server or the nym's
long-term key retroactively decrypts everything. Full Double Ratchet is a poor
fit for a store-and-forward system with a passive, intermittently-online
recipient. One-time prekeys are the right trade:

1. During `Config:`, the nym owner uploads a bundle of N (default 128) X25519
   one-time prekeys, each signed by its Ed25519 identity key, plus one signed
   medium-term prekey as a fallback.
2. `nymd` consumes exactly one prekey per outbound message and **deletes the
   public key from its store immediately**. It never held the private half.
3. Compromise of `nymd` at time T therefore does not decrypt any message sent
   before T. The owner deletes each private prekey after use.
4. When the pool drops below a threshold, `nymd` includes a top-up request in
   the next scheduled outbound message. It does **not** send an out-of-band
   notice — that would be a traffic signal.
5. If the pool is exhausted, fall back to the medium-term prekey and mark the
   message as non-forward-secret in the envelope so the client can warn.

Prekey exhaustion is a denial-of-service vector: an attacker flooding an alias
burns prekeys. Rate-limit per alias, and burn prekeys only for messages that
pass all §3.2 checks.

### 3.7 Legacy mode — existing Zax nymserv clients

**DECIDED: supported.** Existing Zax users can register and operate without a
new client. They get a strictly weaker service, and the registry records which
mode each nym is in.

What legacy nyms do **not** get:

| Feature | Modern | Legacy |
|---|---|---|
| Per-message forward secrecy | Yes (one-time prekeys) | **No** — static OpenPGP key |
| hSub ratchet | Yes | **No** — static subject key, retroactively linkable on seizure |
| Envelope replay counter | Yes | Digest-based replay cache only |
| Approved primitives only | Yes | No (§3.1 scoped exception) |

Legacy mode is a migration ramp, not a parallel product. `nymd` includes a
one-line upgrade pointer in outbound legacy messages, and the deprecation
window is a configured date after which legacy registration is refused
(existing legacy nyms keep working until they migrate or expire).

#### Accepted key material

Allowlist, enforced before any other processing:

- **Signing**: RSA ≥ 2048, Ed25519 (EdDSA)
- **Encryption**: RSA ≥ 2048, X25519 (ECDH cv25519)
- **Rejected unconditionally**: P-256 / P-384 / P-521, Brainpool, secp256k1,
  DSA, ElGamal, RSA < 2048, any key with an expired or missing subkey binding
  signature

Note that "EC only" is *not* the right filter and must not be implemented as
one: most deployed OpenPGP ECDH keys are on NIST curves, so an algorithm-class
check would admit exactly what §2.1 forbids. The filter is a curve/algorithm
allowlist.

#### Parser hardening

The OpenPGP path parses unauthenticated attacker-controlled input, which the
modern path does not. Use `github.com/ProtonMail/go-crypto/openpgp`, and:

1. **Hard size cap before parsing.** Reject anything above the largest bucket
   (§4.3) before a single packet is decoded.
2. **Reject compressed packets outright.** A nym config or message has no
   legitimate need for compression, and accepting it opens decompression-bomb
   and compression-oracle paths. If a real client turns out to compress by
   default, cap the expansion ratio at 20:1 and the absolute output at the
   bucket size, streaming — never decompress to memory first.
3. **Require integrity protection.** Accept SEIPD v1 (MDC) and SEIPD v2 (AEAD)
   only. Reject bare SED packets — that is the EFAIL class, and it is also a
   decryption oracle.
4. **Silent failure, uniform behaviour.** RSA PKCS#1 v1.5 key transport is a
   Bleichenbacher oracle if failure is observable. There is no bounce, no error
   reply, no differential log entry and no differential timing between "bad
   padding", "unknown key" and "bad signature". All three consume the same
   constant work and drop.
5. **No keyring on disk in the GnuPG sense.** Keys live in the registry
   (§2.3) as parsed, validated key material. `nymd` never shells out to `gpg`
   and never touches `~/.gnupg`.

### 3.8 Legacy → modern migration

Compatibility is a ramp, not a second product, so there has to be a way up it
that does not cost the user their alias or their correspondence.

`nymclient migrate` sends an ordinary legacy-mode message — OpenPGP-encrypted
to the server key, signed with the nym's existing OpenPGP key — whose body is a
modern `Config:` block carrying the new Ed25519 identity, the initial hSub key
and a full prekey bundle. The old key authorises the handover; the alias, the
counters and the creation date survive.

`nymservd` then, atomically:

1. Verifies the OpenPGP signature against the stored legacy key
2. Validates the new modern material
3. Flips `Mode` to modern, clears `FlagNoForwardSecrecy`, initialises the hSub
   ratchet at epoch 0 and sets the envelope counter to 0
4. Erases `PGPPublicKey`, `PGPFingerprint` and `LegacySubjectKey`

Migration is one-way. There is no command to go back, because going back would
mean an attacker with the old OpenPGP key could downgrade a nym to a mode
without forward secrecy.

Note what migration cannot repair: posts made while the nym was in legacy mode
remain linkable to the static subject key if that key was captured before the
migration erased it. Migration protects the future, not the past.

### 3.9 The `Config:` grammar

This is the contract between client and server. It is deliberately close to the
Zax syntax so a legacy user reads it without surprise, with the modern fields
added.

```
Config:
From: <alias>@nym.virebent.art
Nym-Command: create
Identity-Key: <base64 Ed25519 public key, 32 bytes>
Hsub-Key: <base64 initial hSub ratchet key K_0, 32 bytes>
Medium-Term-Prekey: <base64 X25519 public key, 32 bytes>
Prekey: <id>:<base64 X25519 public key>
Prekey: <id>:<base64 X25519 public key>
...
```

Rules:

- Header order is not significant; duplicates of any single-valued header are a
  hard reject, not a last-wins.
- `Prekey:` repeats, one per line, up to `PrekeyPoolMax`. IDs must be unique
  within the block and strictly increasing.
- Total block size is capped before parsing, at the smallest bucket (§4.3).
- Unknown headers are a hard reject. Silently ignoring them would let a future
  client believe a feature was accepted when it was dropped.

`Nym-Command:` values:

| Command | Effect |
|---|---|
| `create` | Register a new alias. Fails if taken. |
| `prekeys` | Append to the prekey pool. The only routine command. |
| `rotate-hsub` | Reset the ratchet to a fresh `K_0` at epoch 0. |
| `migrate` | Legacy → modern (§3.8). Legacy mode only. |
| `disable` / `enable` | Toggle `FlagDisabled`. |
| `delete` | Wipe the alias and all key material. Irreversible, no confirmation step. |

There is no confirmation round trip. The original nymserv needed one because a
reply block had to be proven deliverable before it was installed; with no reply
block there is nothing to prove, and the cookie exchange was pure timing
correlation. Authentication is the signature, and that is checked before
anything is written.

**No command produces an error reply.** Every failure — bad signature, taken
alias, malformed header, unknown command — drops silently. The result of a
`Config:` is observed by the client as either the next message arriving in the
shared mailbox or nothing. This is inconvenient and it is not negotiable: any
differential response is an oracle for probing which aliases exist.

The one concession: a successful `create` is acknowledged by the first
scheduled outbound message to the new alias, which the client is already
polling for. It arrives on the ordinary pool schedule, not immediately.

---

## 4. Mixnet tier — world→nym path

The nym→world path is mixed by YAMN. The world→nym path is **not mixed by
anything** unless `nymd` does it. This is where the §2.2 tier applies, and where
the submitted implementation has nothing at all.

### 4.1 Pool

Binomial mix, matching YAMN's own algorithm so the two behave consistently:

- Messages enter a pool on arrival.
- Every interval (default 600 s ± jitter), for each message in the pool,
  release it with probability `p` (default 0.65), subject to a minimum pool
  size (default 12) below which nothing is released except dummies.
- Release order within an interval is shuffled with `crypto/rand`.
- Never flush the pool on shutdown. Persist it encrypted, or accept the loss.

Consequence: worst-case latency for a nym is hours. That is the correct
trade-off and must be stated in the user documentation, not hidden.

### 4.2 Dummy traffic

`nymd` posts to the shared mailbox on a schedule that is **independent of real
traffic volume**: a Poisson process at a fixed rate λ (default 1 post per 20
minutes), drawing from the pool when non-empty and emitting an
indistinguishable dummy when empty. Dummies are real AEAD ciphertexts under a
random key with a random hsub tag; nobody can decrypt them and nobody can
distinguish them.

Without this, the posting rate to a.a.m from your INN2 instance is a direct
side channel on how many nyms you host and how much mail they receive.

### 4.3 Size padding

Pad every outbound ciphertext to the smallest bucket that fits, from a fixed
ladder:

```
4 KiB, 16 KiB, 64 KiB, 256 KiB
```

Reject anything larger at ingest. Four buckets is a deliberate compromise: a
single bucket would be ideal but wastes bandwidth catastrophically for a
newsgroup, and a continuous size distribution leaks. Compress **before**
padding, never after, and be aware that compressing attacker-influenced content
alongside secret content is a CRIME-class oracle — so compress the body only,
never the body concatenated with any key material or tag.

For the nym→world direction, pad to a whole number of YAMN's 17920-byte body
chunks for the same reason.

### 4.4 Abuse handling

This is what closed penet.fi and what gets remailers dropped from the network,
so it needs a decided policy rather than an implicit one. The complaints land
on the YAMN exit remailer, not on you — which means unchecked abuse from your
nyms gets *other operators* pressured and gets you excluded.

The constraint that makes it hard: you keep no logs, so you cannot investigate
after the fact. Everything has to be enforced at the moment of handling, from
state you already hold.

| Control | Mechanism |
|---|---|
| Destination blocklist | Domains and addresses refused at ingest, before the pool. Loaded at unseal, held in RAM. |
| Per-alias rate limit | `DayCount` against `MSGPERDAY`, enforced inside the same critical section as the counter bump — not read afterwards, which was the TOCTOU in the original |
| Global rate limit | A ceiling on total outbound per day, so one compromised alias cannot exhaust the network's tolerance |
| Alias disable | `FlagDisabled`, set through the control socket by the operator |

What is deliberately absent: any content inspection, any retained record of who
sent what, and any complaint-to-alias attribution. If an exit operator reports
abuse, you can disable an alias only if the complaint identifies it — which it
generally will, since the abuse arrives *from* `<alias>@nym.virebent.art`. That
is enough, and it needs no logs.

Publish the policy. An operator who knows you will act on a specific,
identified complaint is an operator who will keep carrying your traffic.

---

### 4.5 What is *not* worth doing

- Do not add application-layer cover traffic on the nym→world path. YAMN
  already pools and already has a dummy packet type. Duplicating it adds
  detectable structure.
- Do not add "randomised delays" as sleeps in a request path. Random delay
  without pooling does not defeat correlation; it only widens the window.
  Pooling is the mechanism; delay is a side effect of it.

---

## 5. Residual attacks that this design does not solve

State these in the documentation. A nym server that claims to defeat a global
passive adversary is lying.

1. **Intersection / statistical disclosure.** An adversary who observes which
   accounts fetch a.a.m over months, combined with which nyms receive mail,
   narrows the set. Mitigation is partial: constant-rate polling by the client,
   full-group download rather than selective fetch, long-lived nyms.
2. **Prekey-pool observation.** The rate at which a nym tops up its prekey pool
   is proportional to how much mail it receives. Mitigation: top up on a fixed
   schedule regardless of consumption, and always upload a full bundle.
3. **Compelled disclosure of the nym registry.** Largely mitigated, not
   eliminated. Seizure of a **powered-off** host yields only ciphertext: the
   sealing key is not on the machine (§2.3). Seizure of a **running** host, or
   compulsion applied to you while it runs, yields the live registry — alias,
   identity public key, current ratchet state `K_n`, remaining prekeys. The
   hSub ratchet means past posts stay unlinkable, but future ones are readable
   until the nyms re-key. RAM-only with re-registration after reboot was
   considered and rejected: it buys almost nothing once the ratchet is in place
   and creates a recurring intersection attack, because every reboot triggers a
   correlated burst of `Config:` messages from exactly the set of active nyms.
4. **The exit remailer sees the plaintext of nym→world mail.** Inherent to the
   Zax model: outbound mail leaves the mix in the clear. End-to-end encryption
   between nym owner and correspondent is the correspondent's problem, not the
   nym server's.
5. **The mail2news gateways.** Injection via YAMN keeps your identity out of
   the `Path` header, but the gateways still see every post and can count them.
   Rotate across several, chosen at random per message. A gateway that logs and
   colludes with an a.a.m observer learns only volume — the hSub tags are
   unlinkable to it.
6. **Legacy nyms are retroactively linkable.** A static subject key means
   seizure at time T identifies every past a.a.m post for that nym (§3.7).
   This is unavoidable in legacy mode and is the strongest argument for the
   deprecation window.

---

## 6. Build and operation

```
[root]     adduser --system --group --home /var/lib/nymserv \
             --shell /usr/sbin/nologin --disabled-password nymserv
[root]     install -d -o nymserv -g nymserv -m 0700 /var/lib/nymserv/{db,keys}
[root]     install -d -o nymserv -g nymserv -m 0700 /run/nymserv
```

Spool on tmpfs, no swap:

```
[root]     # /etc/fstab
           tmpfs /var/lib/nymserv/spool tmpfs rw,nosuid,nodev,noexec,noatime,mode=0700,uid=nymserv,gid=nymserv,size=64M 0 0
[root]     swapoff -a && sed -i '/swap/s/^/#/' /etc/fstab
```

Build with the full hardening set:

```
[user] CGO_ENABLED=0 \
           GOFLAGS="-trimpath -mod=readonly" \
           go build \
             -buildmode=pie \
             -ldflags="-s -w -buildid=" \
             -gcflags="all=-d=checkptr" \
             -tags netgo,osusergo \
             -o nymd ./cmd/nymd
[user] go vet ./... && go test -race ./...
```

`-buildmode=pie` with `CGO_ENABLED=0` requires the `internal` linker; if the
toolchain complains, drop PIE rather than re-enabling cgo.

systemd unit, no root, no network namespace access beyond what is needed:

```
[root]     # /etc/systemd/system/nymd.service — key directives only
           User=nymserv
           Group=nymserv
           NoNewPrivileges=yes
           ProtectSystem=strict
           ProtectHome=yes
           PrivateTmp=yes
           PrivateDevices=yes
           ProtectKernelTunables=yes
           ProtectKernelModules=yes
           ProtectControlGroups=yes
           RestrictAddressFamilies=AF_UNIX AF_INET
           MemoryDenyWriteExecute=yes
           LockPersonality=yes
           SystemCallFilter=@system-service
           SystemCallFilter=~@privileged @resources @obsolete
           ReadWritePaths=/var/lib/nymserv /run/nymserv
           StandardOutput=null
           StandardError=null
```

`StandardOutput=null` and `StandardError=null` are not laziness — they are the
zero-metadata mandate. Do the same for the Postfix pipe transport so the LDA
cannot leak alias names into `mail.log`.

Postfix side, minimal:

```
[root]     # master.cf
           nymlda    unix  -       n       n       -       -       pipe
             flags=DRhu user=nymserv argv=/usr/local/bin/nym-lda ${user}
```

Set `maillog_file` filtering or a dedicated `syslog_name` so that deliveries to
this transport are dropped by rsyslog before they reach disk.

### Unseal after every restart

`nymd` starts sealed and processes nothing until you unseal it. The control
socket is unix-domain and mode 0600; you reach it over SSH through an onion
service, never over a listening TCP port.

```
[user] torsocks ssh -o VerifyHostKeyDNS=no nymadmin@<onion>.onion
[nymadmin] socat - UNIX-CONNECT:/run/nymserv/control.sock
           unseal
           <passphrase, read from the terminal with echo off>
```

`nymadmin` is a second unprivileged account whose only privilege is group
membership allowing it to open the control socket. It is not `nymserv` and
cannot read `/var/lib/nymserv/db`.

Two operational consequences, both intentional:

- An unattended reboot leaves the service sealed and pooling. Mail is accepted
  and queued, nothing is delivered, nothing is lost until the pool cap is hit.
- If you cannot reach the host, the registry stays ciphertext. That is the
  design working, not a failure.

---

## 7. Migration path from the submitted code

Reusable as-is: nothing in the crypto, nothing in the state handling.

Reusable after rework:
- The `Config:` / `Nym-Command:` header grammar and the reserved-name list —
  keeps Zax-client familiarity.
- `checkUsername` — sound, keep the length and charset rules, keep the reserved
  list, add the reserved-prefix check for `confirm`.
- The alias expiry concept (`WARNAFTER` / `DELETEAFTER`), moved into the daemon
  and executed on a schedule that is independent of traffic.

Delete outright:
- Everything reply-block related (`.rb`, `.nrb`, `runConfirm`, cookies).
- `parseLegacyPublicKey` / `processPublicKeyBlock`.
- `runFingerd` — a finger daemon in 2026 is a network-facing attack surface
  that exists to enumerate your nyms. The `list`/`used` commands enumerate them
  over mail too; remove both.
- The `.forward` shell-execution path.
- `wipeFile` and `saferename` — replaced by tmpfs.
- `loadPassphrase` / memguard, unless and until something actually uses it.
  memguard is worth keeping for the `nymd` static X25519 private key, which is
  long-lived in RAM; it is worthless for a value that is never referenced.

---

## 8. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Registry persistence | Sealed on disk, key off-host, manual unseal via onion. No re-registration. hSub ratchet mandatory (§2.3, §3.5) |
| 2 | Legacy Zax compatibility | **Supported** as a deprecated mode (§3.7), plus a new client for modern nyms |
| 3 | Shared mailbox | `alt.anonymous.messages` only. No group on `news.tcpreset.net`. Injection via mail2news through YAMN (§2.2, §3.4) |
| 4 | Latency budget | Accepted as specified: median ≈ 1 h, tail of several hours (§4.1) |

### Still to measure

**Current a.a.m volume and reader population.** The anonymity set of the whole
outbound design is the number of people actually reading the group, not the
existence of the group. If it has decayed to near-zero the model degrades and
the outbound path needs reconsidering. This is a measurement, not an
assumption, and it should be taken before the outbound module is written.

**Working mail2news gateways.** The design needs at least three reachable via
YAMN for the rotation in §3.4 to mean anything. Enumerate and test before
committing to the gateway list.

---

## 9. Build order

1. `internal/registry` — sealed store, Argon2id unseal, memguard key handling,
   atomic rewrite
2. `internal/envelope` — §3.2 modern envelope, uniform-failure open path
3. `internal/replay` — BLAKE2b digest cache, 30-day TTL, persisted in the
   sealed store
4. `cmd/nym-lda` — the ~200 LOC stdin-to-socket agent
5. `cmd/nymd` — ingest, dispatch, control socket
6. `internal/pgpcompat` — §3.7, isolated, fuzzed
7. `internal/pool` — binomial mix, dummy scheduler, bucket padding
8. `internal/outbound` — mail2news submission via `yamn --mail`
9. `nymclient` — the new client (config, prekey generation, ratchet window,
   a.a.m polling over Tor)

Modules 1–3 have no I/O dependencies and are unit-testable in isolation. They
come first.
