# nymserv-ng

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Post-Quantum: NIST FIPS 203](https://img.shields.io/badge/PQ-ML--KEM--768-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)

**nymserv-ng** is a high-assurance, dual-stack pseudonymous email server (nymserver) written in pure Rust. It provides two-way untraceable communications across the Internet by decoupling public email addresses from user identities using cryptographic Reply-Blocks.

It natively introduces a **Post-Quantum channel** powered by **NIST FIPS 203 ML-KEM-768**, ChaCha20-Poly1305, and `pqpg` ASCII Armor, while retaining full backward compatibility with the legacy OpenPGP (GnuPG / Ghionym / Zax) ecosystem.

---

## Live Deployment ("2 novembre")

* **Web Portal (Trilingual EN / IT / FR)**: [https://nymserv-ng.virebent.art/](https://nymserv-ng.virebent.art/)
* **Gemini Capsule**: `gemini://nymserv-ng.virebent.art/`
* **Automated Email Interface**:
  * `help@nymserv-ng.virebent.art` — Automated command suite manual
  * `key@nymserv-ng.virebent.art` — Official server public keys (OpenPGP & ML-KEM-768)
  * `config@nymserv-ng.virebent.art` — Alias registration and key updates
  * `send@nymserv-ng.virebent.art` — Outbound authenticated email dispatch
  * `list@nymserv-ng.virebent.art` — Public alias directory

---

## Key Features

* **Pure Rust Architecture**: 100% safe Rust core (`edition = "2021"`), eliminating memory vulnerabilities and external runtime dependencies.
* **Dual-Stack Cryptography**:
  * **Post-Quantum Native Channel**: NIST FIPS 203 ML-KEM-768 (Kyber) + X25519 hybrid encapsulation, ChaCha20-Poly1305 AEAD, and Ed25519 digital signatures. Uses standard ASCII-armored format compatible with [`pqpg`](https://github.com/gabrix73/pqpg).
  * **Legacy OpenPGP Channel**: Pure-Rust OpenPGP implementation powered by `sequoia-openpgp` (RSA-4096 / Ed25519) supporting standard PGP-encrypted `Config:` blocks and Reply-Blocks.
* **Flexible Reply-Blocks**:
  * **Direct Delivery**: Delivers encrypted emails directly to recipient mailboxes.
  * **Mixnet Multi-Hop Routing**: Supports nested YAMN and Mixmaster encrypted reply-blocks, allowing users to receive replies without revealing their real email address or IP even to the nym server operator.
* **Embedded ACID Database**: Powered by `redb` for zero-maintenance, zero-dependency, crash-safe embedded key-value storage.
* **Memory Hygiene**: Uses `zeroize` and `secrecy` to ensure private cryptographic material is scrubbed from RAM immediately after use.
* **MTA & Container Integration**: Works natively with Postfix / OpenSMTPD via LMTP or pipe delivery agent (`nymserv-lda`), running inside an isolated rootless container.

---

## Server Public Keys

The server operates with dual keys for both channels:

1. **Post-Quantum Channel (`nymserver-pq-pubkey.asc`)**:
   * **Algorithm**: NIST FIPS 203 ML-KEM-768 + X25519 + Ed25519 (Hybrid)
   * **Format**: ASCII Armor (`-----BEGIN PQPG PUBLIC KEY-----`)
   * **SHA256**: `277df4d834cb0cbd6d4e1d3e4be3b50beb10d6b59059240a4b11c225108d89a3`
   * **Download**: [https://nymserv-ng.virebent.art/nymserver-pq-pubkey.asc](https://nymserv-ng.virebent.art/nymserver-pq-pubkey.asc)

2. **Legacy OpenPGP Channel (`nymserver-openpgp.asc`)**:
   * **Algorithm**: RSA 4096-bit
   * **Key ID**: `0x789C19FA8654FD1B`
   * **Format**: OpenPGP ASCII Armor (`-----BEGIN PGP PUBLIC KEY BLOCK-----`)
   * **Download**: [https://nymserv-ng.virebent.art/nymserver-openpgp.asc](https://nymserv-ng.virebent.art/nymserver-openpgp.asc)

Both keys can also be retrieved automatically by sending a blank email to `key@nymserv-ng.virebent.art`.

---

## Repository Structure

```
.
├── Cargo.toml                  # Cargo dependencies and workspace metadata
├── Dockerfile                  # Multi-stage production container build
├── docker-compose.yml          # Container topology for deployment
├── src/
│   ├── lib.rs                  # Core library exports
│   ├── bin/
│   │   ├── nymserv-lda.rs      # Local Delivery Agent (MTA pipe processor)
│   │   ├── nymserv-ctl.rs      # Administrative and debugging CLI
│   │   └── nymservd.rs         # Background daemon coordinator
│   ├── crypto/
│   │   ├── mod.rs              # Cryptographic abstraction layer
│   │   └── pqpg.rs             # ML-KEM-768, X25519, AEAD & ASCII Armor engine
│   ├── protocol/
│   │   ├── mod.rs              # Protocol definitions
│   │   └── ghio.rs             # Ghionym/Zax Config parser and envelope codec
│   ├── storage/
│   │   ├── mod.rs              # Database interfaces
│   │   └── db.rs               # redb storage implementation
│   └── mta/
│       └── mod.rs              # Outbound SMTP dispatcher
└── www/                        # Static web & Gemini capsules (EN/IT/FR)
```

---

## Building from Source

### Prerequisites

* Rust 1.80 or later (MSRV)
* Cargo and standard build tools (`build-essential` on Debian/Ubuntu)

### Build Commands

```bash
# Clone the repository
git clone https://github.com/gabrix73/nymserv-ng.git
cd nymserv-ng

# Build release binaries
cargo build --release

# Binaries produced in target/release/:
# - nymserv-lda (MTA pipe ingest)
# - nymserv-ctl (CLI management tool)
# - nymservd    (Service daemon)
```

---

## Quickstart: Creating a Pseudonym

### Option A: Post-Quantum Channel (Recommended)

1. **Obtain the `pqpg` tool**:
   ```bash
   # Download Linux x86_64 binary
   curl -sO https://nymserv-ng.virebent.art/bin/pqpg-linux-amd64
   chmod +x pqpg-linux-amd64 && sudo mv pqpg-linux-amd64 /usr/local/bin/pqpg
   ```

2. **Generate your PQ keypair**:
   ```bash
   mkdir -p ~/Nym-pq && cd ~/Nym-pq
   pqpg keygen
   # Generates identity.pub and identity.key
   ```

3. **Fetch server public key**:
   ```bash
   curl -sO https://nymserv-ng.virebent.art/nymserver-pq-pubkey.asc
   ```

4. **Prepare `config.txt`**:
   ```text
   Config:
   From: youralias@nymserv-ng.virebent.art
   Public-Key:
   -----BEGIN PQPG PUBLIC KEY-----
   ... (contents of identity.pub) ...
   -----END PQPG PUBLIC KEY-----
   Reply-Block:
   ::
   Anon-To: your_real_email@secure-provider.org

   Nym-Commands: +cryptrecv +pqsend
   ```

5. **Encrypt and dispatch**:
   ```bash
   pqpg encrypt --recipient-key nymserver-pq-pubkey.asc config.txt > config.asc
   # Send config.asc to config@nymserv-ng.virebent.art
   ```

### Option B: Legacy OpenPGP Channel (GnuPG)

1. **Generate your GPG key**:
   ```bash
   gpg --quick-generate-key "youralias <youralias@nymserv-ng.virebent.art>" rsa4096
   ```

2. **Fetch server OpenPGP key**:
   ```bash
   curl -sO https://nymserv-ng.virebent.art/nymserver-openpgp.asc
   gpg --import nymserver-openpgp.asc
   ```

3. **Prepare `config.txt`**:
   ```text
   Config:
   From: youralias@nymserv-ng.virebent.art
   Public-Key:
   -----BEGIN PGP PUBLIC KEY BLOCK-----
   ... (exported armored public key) ...
   -----END PGP PUBLIC KEY BLOCK-----
   Reply-Block:
   ::
   Anon-To: your_real_email@secure-provider.org

   Nym-Commands: +cryptrecv
   ```

4. **Encrypt with server key and send**:
   ```bash
   gpg --armor --recipient "0x789C19FA8654FD1B" --encrypt config.txt
   # Send config.txt.asc to config@nymserv-ng.virebent.art
   ```

---

## Licence

Licensed under the **Affero General Public License v3.0** ([AGPL-3.0-only](LICENSE)).

Author: **Gab Virebent** `<gabriel1@virebent.art>`
Website: [https://virebent.art](https://virebent.art)
