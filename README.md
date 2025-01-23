# RustPass

## About

This is a password manager written entirely in Rust. It is modeled after [KeePass](https://keepass.info), but works as a command line interface and has slightly reduced features. 

*** Currently in early development ***

## Usage

RustPass works with vaults, which have the `.rpdb` file extension. These hold all the keys, and are stored as protobufs.

- To create a vault, run `rustpass create -n <NAME> -p <PATH>`.
- To open a vault, run `rustpass open`.
- After opening the vault, it can be navigated with usual UNIX file commands
    - `cd` to enter subdirectories
    - `ls` to list all keys and directories
    - `mkdir` create subdirectories
    - To get the value associated with a key, use `get <KEYNAME>`. It will be copied to the clipboard and deleted after a set number of seconds.
- To adjust the configuration, such as the time a value will be kept in the clipboard, run `rust config`. Run `rust config --help` for more details.

For more detailed explanations, use `rustpass --help`.

** *NOTE*: nested directories are not supported. **

## Technical Specifications

### .rpdb File Format

The `.rpdb` files represent entire vaults. They follow the following structure

#### Header

| Name | ID | Type | Description|
|:-----|:---|:-----|:-----------|
| Signature | 1 | UInt32 | Must be 0x3A7F9C42 |
| Version | 2 | UInt16 | Version number: 8 bits for the major version, 8 for the minor. <br> E.g. 0x0511 is version 5.17. |
| Header End | 3 | UInt32 | Must be 0x0B11E000. |



They are encoded as protobuffs.






