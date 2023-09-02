# SQLCipherv3Decryptor

## Overview
SQLCipherDecryptor is a .NET library designed to handle decryption of SQLCipher-encrypted databases. It includes both synchronous and asynchronous methods to decrypt SQLCipher version 3.x databases. It offers utility functions to derive encryption and HMAC keys, validate decrypted headers, and more. This library employs parallelism, which allows the decryption oepration to run incredibly fast (~500ms).

## Features
- Supports SQLCipher 3.x databases.
- Synchronous and Asynchronous decryption methods.
- Utility functions for key derivation, HMAC validation, and more.
- Page-level decryption.
- HMAC verification for encrypted pages.
- Thorough error handling.

## Usage
You can use the application provided in the release tab.
```SQLCipherDecryptor <input_file_path> <output_file_path> <password>```

Alternatively, you can use the library branch.
### Synchronous
```c#
DecryptDefault(string sourceFileName, string outputFileName, string passwordString);
```
### Asynchronously
```c#
await DecryptDefaultAsync(string sourceFileName, string outputFileName, string passwordString);
```
## Limitations
- Only works for SQLCipher v3.0
- Low-level of customization:
  -  Assumes the use of SHA-1 for HMAC algorithm (PBKDF2).
  -  Assumes the use of SHA-1 for KDF algorithm
  -  64,000 KDF iterations
  -  1,024 Page size
  -  Plaintext header size is 0

## Contributing
This code was wholly written by me, but fully translated from Python. An enormous thank you to [@bssthu](https://github.com/bssthu), who wrote [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher). I have based my code largely off of this repository, with some modifications for it to be compatible with C#.