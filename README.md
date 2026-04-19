# Muninn

In-memory secrets manager in C++ using memory protection primitives and libsodium.

## Building

```bash
make
make debug
make clean
```

## Dependencies

- libsodium

```bash
brew install libsodium
```

## Usage

```bash
./muninn
```

## TODO:

- [x] Secure memory allocation (mmap + mlock)
- [x] Memory sealing (mprotect)
- [x] Secure erasure
- [x] Argon2id key derivation
- [x] AES-256-GCM encrypted persistence
- [x] Hidden password input
- [ ] CLI interface
- [ ] Review memory release