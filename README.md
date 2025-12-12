# 🔐 Secure Encryption CLI Tool (AES-256-GCM)

A lightweight and secure Python command-line tool for encrypting and decrypting files using **AES-256-GCM** with **PBKDF2 (100k iterations)**.  
Also supports generating **RSA-4096 keypairs** for hybrid-encryption demonstrations.

---

## ✨ Features
- AES-256-GCM authenticated encryption  
- PBKDF2-HMAC-SHA256 key derivation  
- Automatic salt + nonce generation  
- Password-based encryption/decryption  
- RSA-4096 keypair generator  
- Simple and stable CLI interface  

---
🛠 Usage

Encrypt a File
python file.py encrypt <input_file> <output_file>

Example
python file.py encrypt secret.txt secret.enc

Decrypt a File
python file.py decrypt <encrypted_file> <output_file>

Example
python file.py decrypt secret.enc decrypted.txt

Generate RSA 4096-bit Keypair
python file.py genkey <private_key.pem> <public_key.pem>

Example
python file.py genkey my_private.pem my_public.pem


AES-256-GCM encryption/decryption logic

PBKDF2-based 32-byte key derivation

RSA-4096 keypair generation

A complete argparse-based command-line interface
