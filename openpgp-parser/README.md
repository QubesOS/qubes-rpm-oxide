# A Strict OpenPGP parser

`openpgp-parser` is a **strict** parser for OpenPGP (RFC 4880) data.
It is primarily intended to validate data before passing it to another parser,
often written in C.  This helps protect against exploits that use invalid data
to take advantage of vulnerabilities in that parser.

`openpgp-parser` was written for use with RPM, which has its own parser for
OpenPGP signatures and keys.  However, this parser has had memory unsafety
vulnerabilities in the past, so I wrote this crate to validate OpenPGP
signatures before passing them to RPM.

`openpgp-parser` has the following features:

- Strict by default.  `openpgp-parser` only accepts messages it knows to be
  syntactically correct.  `openpgp-parser` deliberately violates Postel’s Law
  in this regard.
- `#![no_std]` support.  By default, `openpgp-parser` does not use the standard
  library at all.
- No built-in cryptography.  As the name implies, `openpgp-parser` is a *parser*
  for OpenPGP data.  It is not an OpenPGP implementation itself.
- No dependencies except `libcore`.
- No unsafe code.
- A reusable buffer abstraction as part of the public API.  This buffer
  abstraction is used internally in `openpgp-parser`, but is also useful in its
  own right.
- Packets using obsolete cryptographic algorithms are rejected.  Note that this
  does not (yet) apply to packets that use secure algorithms (such as RSA) with
  keys that are too short.
- Some protection from signature malleability.  OpenPGP signatures can contain
  one or more unhashed subpackets, which are not protected by the signature.
  Trusting data from these subpackets can be a source of vulnerabilities.

  `openpgp-parser` only allows the Key ID to be an unhashed subpacket.
  Furthermore, `openpgp-parser` *requires* that each signature have exactly one
  Key ID subpacket, so if a signature is modified by removing that subpacket,
  `openpgp-parser` will reject it.  If a hashed fingerprint subpacket is
  provided, `openpgp-parser` will check the key ID subpacket against it.

  Note that this protection does not apply to the MPIs that constitute the
  signature itself.  That is the responsibility of the cryptography
  implementation.
- `openpgp-parser` is written in safe Rust, so it is not subject to the memory
  unsafety bugs that plague C and C++ programs.
- Every commit to `openpgp-parser` is cryptographically signed.
