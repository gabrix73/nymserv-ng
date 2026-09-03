# nymserv-ng

A pseudonymous email server for the live [YAMN](https://github.com/crooks/yamn)
mix network. Protocol-compatible with Zax-style
[nymserv](https://github.com/crooks/nymserv), independently implemented in Go,
with modern primitives, per-message forward secrecy and a mix pool on the
delivery path.

**Status: early. Not deployable. Do not use this for a real pseudonym.**

The registry, envelope, ingest and daemon skeleton work and are tested. The
message pool, the outbound path, the OpenPGP compatibility layer and the client
are not written yet. See [Roadmap](#roadmap).

---

## What it does differently

YAMN is a forward-only Type II mix network: it has no reply blocks and no
SURBs. That single fact determines the whole architecture, and it is why the
reply-block design of the original nym.alias.net nymserv cannot be ported to it.

Messages **from** a nym travel out over YAMN as ordinary forward messages.
Messages **to** a nym are encrypted, padded, pooled and published to a shared
mailbox (`alt.anonymous.messages`) that the owner polls over Tor. The recipient
anonymity set is every reader of that mailbox rather than one reply-block
holder, and there is no return path on the server for anyone to seize.

Against the original implementation:

| | Zax nymserv | nymserv-ng |
|---|---|---|
| Crypto | OpenPGP / GnuPG | X25519, XChaCha20-Poly1305, Ed25519, BLAKE2b |
| Forward secrecy | None | Per-message, via one-time prekeys |
| Subject tags | Static key | Ratcheted; past posts unlinkable after seizure |
| Server state | Files on disk | Sealed registry, key held off-host |
| Delivery timing | Immediate | Binomial mix pool with dummy traffic |
| Server identity key | On the server | Offline; the host cannot sign for itself |

Existing Zax users are supported in a deprecated legacy mode, and can migrate
in place without losing their alias.

## Documentation

[`doc/design.md`](doc/design.md) is the specification: threat model, wire
formats, key hierarchy, pool parameters, and an explicit list of the attacks
this design does **not** defeat. Read section 5 before trusting it with
anything.

## Layout

```
cmd/nymservd            daemon: ingest, dispatch, control socket
cmd/nymserv-lda         MTA delivery agent: stdin to socket, nothing else
cmd/nymserv-keytool     OFFLINE identity key and bundle signing
cmd/nymserv-democlient  test harness -- not the real client
internal/registry       sealed registry, hSub ratchet, prekeys, replay cache
internal/envelope       inbound envelope, server key bundles
internal/ingest         wire format between the agent and the daemon
```

## Build

Requires Go 1.23 or later.

```
[user]  git clone https://git.virebent.art/virebent/nymserv-ng
[user]  cd nymserv-ng
[user]  go vet ./...
[user]  go test -race ./...
[user]  CGO_ENABLED=0 GOFLAGS="-trimpath -mod=readonly" \
          go build -ldflags="-s -w -buildid=" -tags netgo,osusergo -o bin/ ./cmd/...
```

Fuzz the envelope parser, which is the only component that reads
attacker-controlled input on the modern path:

```
[user]  go test -run xxx -fuzz FuzzOpen -fuzztime 5m ./internal/envelope/
```

There are deliberately no build or deployment scripts. Every step is meant to
be run and understood individually.

## First run

`nymservd` starts sealed and processes nothing until the registry passphrase is
supplied over the control socket. The passphrase is never stored on the host.

```
[root]      adduser --system --group --home /var/lib/nymserv \
              --shell /usr/sbin/nologin --disabled-password nymserv
[root]      install -d -o nymserv -g nymserv -m 0700 /var/lib/nymserv/db /run/nymserv
```

The spool must be on tmpfs with swap disabled. Overwriting a file in place is
not reliable deletion on a journalled or copy-on-write filesystem, so the only
way a deleted spool file stays gone is for it never to have reached stable
storage.

```
[root]      # /etc/fstab
            tmpfs /var/lib/nymserv/spool tmpfs rw,nosuid,nodev,noexec,noatime,mode=0700,uid=nymserv,gid=nymserv,size=64M 0 0
[root]      swapoff -a
```

On an **offline** machine, generate the server identity. Its private half must
never exist on the server:

```
[user]      nymserv-keytool identity-gen -dir ./offline
```

Create the registry and start the daemon:

```
[nymserv]   nymservd -init -db /var/lib/nymserv/db/registry.bin
[nymserv]   nymservd -db /var/lib/nymserv/db/registry.bin \
              -spool /var/lib/nymserv/spool/out \
              -ingest-socket /run/nymserv/ingest.sock \
              -control-socket /run/nymserv/control.sock
```

Unseal and set up keys over the control socket, reached through an onion
service:

```
[nymadmin]  socat - UNIX-CONNECT:/run/nymserv/control.sock
            unseal
            <passphrase>
            set-identity <identity public key from the offline machine>
            rotate
            keys
```

`rotate` prints the new X25519 public key. Take it to the offline machine,
sign it, and import the result:

```
[user]      nymserv-keytool bundle-sign -identity ./offline/identity.key -enc-pub <hex>
[nymadmin]  import-bundle <base64>
```

The daemon can verify a bundle but can never produce one. That is the point of
the split: an attacker who compromises the running host can read mail, but
cannot redirect clients to a key they control.

## Roadmap

Done: registry, envelope, server key hierarchy and rotation, ingest path,
daemon skeleton, control socket.

Next, in order:

1. `internal/pool` — binomial mix, dummy scheduler, bucket padding. **Until
   this exists there is no mixing at all**: arrival and release are correlated
   one to one.
2. `internal/outbound` — mail2news submission through YAMN
3. `internal/pgpcompat` — legacy OpenPGP mode, isolated and fuzzed
4. `Config:` grammar handling (design §3.9)
5. `nymclient` — the real client: prekeys, ratchet window, polling over Tor

## Attribution

The Zax-style nymserver model, the `Config:` grammar this implementation
follows, and the YAMN network itself are the work of Steve Crook (Zax). This is
an independent implementation, not a fork; see [NOTICE](NOTICE).

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE).
