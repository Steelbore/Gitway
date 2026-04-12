# Notices and Acknowledgments

Gitway (Copyright © 2026 Mohamed Hammad) is free software licensed under the
GNU General Public License, version 3 or later.  See [LICENSE](LICENSE).

---

## russh

Gitway is built on top of **russh**, a pure-Rust SSH client and server library.

```
Copyright 2016 Pierre-Étienne Meunier
Licensed under the Apache License, Version 2.0
```

russh was originally written by **Pierre-Étienne Meunier** as part of the
[Pijul](https://pijul.org/) version-control project and continues to be
maintained at <https://github.com/warp-tech/russh> by Warp Technologies and
the open-source community.

### What Gitway uses from russh

| Component | Purpose |
|---|---|
| `russh` | SSH handshake, key exchange, authentication, exec channel |
| `russh-cryptovec` | Mlock-backed, zeroize-on-drop buffer for key material |
| `russh-keys` | OpenSSH key decoding and agent protocol |

Gitway uses russh 0.59 from crates.io with the `aws-lc-rs` cryptography backend,
which provides post-quantum cryptography (PQC) support without requiring CMake,
bindgen, or Go for non-FIPS builds.

---

## aws-lc-rs

The `aws-lc-rs` crate provides cryptographic primitives (AES-GCM,
ChaCha20-Poly1305, SHA-2, HKDF, key generation, and post-quantum algorithms)
used by russh.

```
Copyright Amazon.com, Inc. or its affiliates
Licensed under the Apache License, Version 2.0 or ISC License
```

<https://github.com/aws/aws-lc-rs>

aws-lc-rs is a Rust wrapper around AWS-LC, a general-purpose cryptographic
library maintained by AWS that includes FIPS 140-3 validated implementations
and post-quantum cryptography primitives.

---

## Other dependencies

The complete list of transitive dependencies and their licences can be
generated with:

```sh
cargo license --all-features
```

Key runtime dependencies and their licences:

| Crate | Version | License |
|---|---|---|
| `tokio` | 1.x | MIT |
| `thiserror` | 2.x | MIT OR Apache-2.0 |
| `clap` | 4.x | MIT OR Apache-2.0 |
| `rpassword` | 7.x | MIT |
| `zeroize` | 1.x | MIT OR Apache-2.0 |
| `dirs` | 6.x | MIT OR Apache-2.0 |
| `env_logger` | 0.11.x | MIT OR Apache-2.0 |
| `mimalloc` | 0.1.x | MIT |
| `log` | 0.4.x | MIT OR Apache-2.0 |
