# d-ipcrypt2

A D bindings of [IPCrypt2](https://github.com/jedisct1/ipcrypt2), a simple and secure IP address obfuscation scheme.

IPCrypt2 is a format-preserving encryption scheme for IPv4 and IPv6 addresses. It allows IP addresses to be encrypted while maintaining their format, making it suitable for logging and data retention purposes where IP addresses need to be pseudonymized.

Features:
- Format-preserving encryption for both IPv4 and IPv6 addresses
- Cryptographically secure using AES-256 as the underlying cipher
- Preserves subnets: addresses sharing a prefix are encrypted to addresses sharing the same prefix
- Deterministic: same input and key always produces the same output
- Fast and constant-time operation


## Known Implementations

| Name                                                                                                            | Language   |
| --------------------------------------------------------------------------------------------------------------- | ---------- |
| [Reference implementation](https://github.com/jedisct1/draft-denis-ipcrypt/tree/main/reference-implementations) | Python     |
| [ipcrypt2](https://github.com/jedisct1/ipcrypt2)                                                                | C          |
| [rust-ipcrypt2](https://github.com/jedisct1/rust-ipcrypt2)                                                      | Rust       |
| [ipcrypt-js](https://www.npmjs.com/package/ipcrypt)                                                             | JavaScript |
| [go-ipcrypt](https://github.com/jedisct1/go-ipcrypt)                                                            | Go         |
| [zig-ipcrypt](https://github.com/jedisct1/zig-ipcrypt)                                                          | Zig        |

## Acknowledgements

- [jedisct1](https://github.com/jedisct1/) - for the original implementation