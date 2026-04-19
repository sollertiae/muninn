# Muninn

A command-line secrets manager written in C++ with a focus on memory security and cryptographic correctness.

Secrets are stored in mlock'd memory pages that cannot be swapped to disk, encrypted at rest using AES-256-GCM with Argon2id key derivation, and securely erased from memory when the program exits.

## Building

```bash
make
make debug
make clean
```

## Dependencies

- libsodium

```bash
brew install libsodium     # macOS
apt install libsodium-dev  # Linux
```

## Usage

```bash
./muninn create -o <vault>          # create new vault
./muninn add -i <vault>             # add a secret
./muninn get -i <vault> -k <key>    # copy secret to clipboard
./muninn delete -i <vault> -k <key> # delete a secret
./muninn list -i <vault>            # list all keys
./muninn help                       # show all commands
```

## TODO:

- [x] Secure memory allocation (mmap + mlock)
- [x] Memory sealing (mprotect)
- [x] Secure erasure
- [x] Argon2id key derivation
- [x] AES-256-GCM encrypted persistence
- [x] Hidden password input
- [X] CLI interface
- [ ] Review memory release
- [ ] Clear clipboard