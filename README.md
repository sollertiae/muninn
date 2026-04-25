# Muninn

A command-line secrets manager written in C++ with a focus on memory security and cryptographic correctness.

## Security Model

Muninn stores secrets in memory pages locked with `mlock`, preventing them from being swapped to disk. Pages are sealed with `mprotect` when not actively accessed, and all sensitive memory is zeroed with `sodium_memzero` before release. It uses Argon2id to derive a cryptographic key at runtime, which is used with AES-256-GCM for authenticated encryption of the vault file. The process hardens itself against inspection by preventing ptrace attachment.

## Building

```bash
make
make debug
make clean
```

## Dependencies

- libsodium
- xclip (Linux)

**macOS:**
```bash
brew install libsodium 
```

**Linux:**
```bash
sudo apt install libsodium-dev xclip
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
- [X] Review memory release
- [ ] Clear clipboard