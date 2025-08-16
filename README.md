# Password Protection Library

A small Rust library for password-based encryption/decryption using:

- **PBKDF2-HMAC-SHA256** for key derivation  
- **AES-256-GCM** for authenticated encryption  

---

## Features

- Derives keys from a user password + random salt  
- Encrypts with AES-256-GCM (confidentiality + integrity)  
- Self-contained output: `[salt | nonce | ciphertext+tag]`  
- Simple API with round-trip tests included  

---

## Usage

```rust
use password_protect::{lock_data, unlock_data};

let password = "correct horse battery staple";
let data = b"My secret data";

let encrypted = lock_data(data, password);
let decrypted = unlock_data(&encrypted, password).unwrap();

assert_eq!(decrypted, data);
