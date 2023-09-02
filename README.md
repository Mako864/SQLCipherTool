# SQLCipherv3 Library/Tool

## Overview
SQLCipherDecryptor is a .NET library designed to handle decryption of SQLCipher-encrypted databases. It includes both synchronous and asynchronous methods to decrypt and encrypt SQLCipher version 3.x databases. It offers utility functions to derive encryption and HMAC keys, validate decrypted headers, and more. This library employs parallelism, which allows the decryption operation to run relatively fast (~500ms).

## Features
- Supports encryption & decryption
- Supports SQLCipher 3.x databases.
- Synchronous and Asynchronous decryption methods.
- Utility functions for key derivation, HMAC validation, and more.
- Page-level decryption.
- HMAC verification for encrypted pages.
- Thorough error handling.

## Usage
The library is capable of decryption and encryption, with the exception that encryption is dependent on the [SQLitePCLRaw.bundle_e_sqlcipher](https://www.nuget.org/packages/SQLitePCLRaw.bundle_e_sqlcipher) NuGet package. If you are only looking for low-level code, you are better off only downloading the decryptor .dll.
### Decryption
You can use the application provided in the release tab.
```app.exe <input_file_path> <output_file_path> <password>```

Alternatively, you can use the library branch.
#### Synchronous
```c#
DecryptDefaultAsync(string sourceFileName, string outputFileName, string passwordString);
```
#### Asynchronous
```c#
await DecryptDefaultAsync(string sourceFileName, string outputFileName, string passwordString);
```
### Encryption
You can use the application provided in the release tab.
```app.exe <input_file_path> <output_file_path> <password>```
Alternatively, you can use the library branch.
#### Synchronous
```c#
EncryptDatabase(string inputFilePath, string outputFilePath, string key)
```

## Limitations
- Only works for SQLCipher v3.0
- Low-level of customization:
  -  Assumes the use of SHA-1 for HMAC algorithm (PBKDF2).
  -  Assumes the use of SHA-1 for KDF algorithm.
  -  64,000 KDF iterations.
  -  1,024 Page size.
  -  Plaintext header size is 0.
- Encryption library has a dependancy on SQLitePCLRaw.bundle_e_sqlcipher.

## Contributing
This code was wholly written by me, but fully translated from Python. An enormous thank you to [@bssthu](https://github.com/bssthu), who wrote [pysqlsimplecipher](https://github.com/bssthu/pysqlsimplecipher). I have based my code largely off of this repository, with some modifications for it to be compatible with C#.
