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

𝐄𝐍𝐂𝐑𝐘𝐏𝐓 𝐀 𝐅𝐈𝐋𝐄:

python3 file.py encrypt <input_file> <output_file>

Example:
python3 file.py encrypt secret.txt secret.enc

𝐃𝐄𝐂𝐑𝐘𝐏𝐓 𝐀 𝐅𝐈𝐋𝐄:

python3 file.py decrypt <encrypted_file> <output_file>

Example:
python3 file.py decrypt secret.enc decrypted.txt

𝐆𝐄𝐍𝐄𝐑𝐀𝐓𝐄 𝐑𝐒𝐀 𝟒𝟎𝟗𝟔-𝐁𝐈𝐓 𝐊𝐄𝐘𝐏𝐀𝐈𝐑:

python3 file.py genkey <private_key.pem> <public_key.pem>

Example:
python3 file.py genkey my_private.pem my_public.pem
