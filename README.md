# Public key authenticated encryption in Rust

This is an example implementation of public key authenticated encryption (PKAE)
in Rust using only the high performance [Ring](https://github.com/briansmith/ring)
cryptography library.

PKAE enables a person or service X to send confidential data to another person
or service Y such that only Y can read the data. Y can also verify that the data
originated from X and not an impostor.

## Motivation

Both the [libsodium](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
and [openssl](https://www.openssl.org/docs/manmaster/man7/evp.html) libraries
can perform PKAE using specific primitives, however these are easy to misuse and
call a lot of potentially unsafe C code. Also, the Rust interfaces to libsodium
and openssl require the full libraries which substantially increase code size.
Finally, many Rust crates already depend on `ring` directly or transitively,
including `rustls` and by extension `actix-net`, `actix-web`, `tokio-rustls`, 
`h2`, and `reqwest`. Writing PKAE functionality using `ring` avoids having to
bring in a separate dependency.

## Building and running the code

Type `cargo run`. If the code encrypts and decrypts the message successfully, it
should print `Ok`.
