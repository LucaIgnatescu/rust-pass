# RustPass

## About

This is a password manager written entirely in Rust. It is modeled after [KeePass](https://keepass.info), but works as a more opinionated command line application.  

***Currently in early development***

## Usage

RustPass works with vaults, which have the `.rpdb` file extension. These hold all the keys, and are stored as protobufs.

- To create a vault, run `rustpass create -n <NAME> -p <PATH>`
- To open a vault, run `rustpass open <PATH_TO_FILE>`
- After opening the vault, it can be navigated with usual UNIX file commands:
    - `cd` to enter subdirectories
    - `ls` to list all keys and directories
    - `mkdir` create subdirectories
    - `get <KEYNAME>` to get the value associated with a key. It will be copied to the clipboard and deleted after a set number of seconds
- To adjust the configuration, such as the time a value will be kept in the clipboard, run `rustpass config`. Run `rustpass config --help` for more details

For more detailed explanations, use `rustpass --help`

***NOTE*: nested directories are not supported.**

## Technical Specifications

### .rpdb File Format

Each `.rpdb` file represens an entire vault. It is encoded as [protobuf](https://protobuf.dev).
Check the `/src/proto` for the definitions. More details are provided in the Header section. 

General outline of a `.rpdb` file:

1. Header
1. HMAC-SHA-256 hash of Header. 
1. HMAC block stream.

#### Header

| Name | ID | Type | Description|
|:-----|:---:|:-----:|:-----------|
| Signature | 1 | UInt32 | Must be 0x3A7F9C42 |
| Version | 2 | UInt16 | Version number: 8 bits for the major version, 8 for the minor. <br> 
E.g. 0x0511 corresponds to 5.17. |
| Master Salt | 3 | Byte[32] | Salt for computing keys |
| Encryption IV | 4 | Byte[12] | IV for ChaCha20 |
| KDF Parameters | 5 | KDFParams | Parameters for the argon2 key generation | 
| Chunk Size | 6 | UInt32 | Size of input data chunks in block stream |

KDF Parameters follow the following structure:

| Name | ID | Type | Description|
|:-----|:---:|:-----:|:-----------|
| Iterations | 1 | UInt32 | # iterations |
| Memory | 2 | UInt32 | Memory |
| Parallelism | 3 | UInt32 | Parallelism |
| Salt | 4 | Byte[] | Salt |

Everything is encoded as a 

### Key Derivation

*NOTE: `‖` denotes concatenation*

1. Compute `R`: SHA-256 hash of master password.
1. Compute `T`: Transformation of `R` using Argon2d.

Then the rest of the keys are computed as follows:
1. ChaCha20 key: `SHA-256(S ‖ T)`
1. HMAC header key: `SHA-512(0xFFFFFFFFFFFFFFFF ‖ SHA-512(S ‖ T ‖ 0x01))`
1. HMAC block key for `i`'th chunk: `SHA-512(i ‖ SHA-512(S ‖ T ‖ 0x01))`

## Security

### Entropy Pools

### Process Memory Protection

Process memory is encrypted using ChaCha20. Parameters are regenerated on every `open`.
