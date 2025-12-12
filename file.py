#!/usr/bin/env python3
"""
Secure Encryption/Decryption CLI Tool
Advanced AES-256-GCM implementation with PBKDF2 key derivation
For cybersecurity demos and production use
Created by @akshay5679 - github
"""

import argparse
import base64
import getpass
import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

class SecureCryptoCLI:
    def __init__(self):
        self.salt = None
        self.nonce = None
        
    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        """PBKDF2 key derivation with 100k iterations -> returns raw 32-byte key"""
        if salt is None:
            self.salt = secrets.token_bytes(16)
        else:
            self.salt = salt
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 raw key length
            salt=self.salt,
            iterations=100000,
        )
        # return raw bytes (not base64), AESGCM expects a 32-byte key
        return kdf.derive(password.encode())

    def encrypt_file(self, input_file: str, output_file: str, password: str):
        """Encrypt file using AES-256-GCM"""
        key = self.derive_key(password)
        aesgcm = AESGCM(key)
        
        with open(input_file, 'rb') as f:
            data = f.read()
            
        self.nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(self.nonce, data, None)
        
        # Header: salt(16) + nonce(12) + ciphertext
        header = self.salt + self.nonce + ciphertext
        
        with open(output_file, 'wb') as f:
            f.write(header)
        
        print(f"✅ File encrypted: {input_file} → {output_file}")
        print(f"🔒 Salt: {base64.b64encode(self.salt).decode()}")
        print(f"🔑 Use same password to decrypt")

    def decrypt_file(self, input_file: str, output_file: str, password: str):
        """Decrypt file using AES-256-GCM"""
        with open(input_file, 'rb') as f:
            header = f.read()
            
        if len(header) < 28:
            print("❌ Invalid encrypted file")
            return
            
        self.salt = header[:16]
        self.nonce = header[16:28]
        ciphertext = header[28:]
        
        key = self.derive_key(password, self.salt)
        aesgcm = AESGCM(key)
        
        try:
            plaintext = aesgcm.decrypt(self.nonce, ciphertext, None)
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
                
            print(f"✅ File decrypted: {input_file} → {output_file}")
            
        except Exception as e:
            print("❌ Decryption failed - wrong password or corrupted file")
            print(f"   Error: {e}")

    def generate_keypair(self, private_file: str, public_file: str):
        """Generate RSA 4096-bit keypair for hybrid encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        public_key = private_key.public_key()
        
        # Save private key (password protected) - ask twice to confirm
        while True:
            password = getpass.getpass("Enter private key password: ")
            password2 = getpass.getpass("Confirm private key password: ")
            if password != password2:
                print("Passwords do not match. Try again.")
            else:
                break

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        with open(private_file, 'wb') as f:
            f.write(pem_private)
            
        # Save public key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_file, 'wb') as f:
            f.write(pem_public)
            
        print(f"✅ RSA keypair generated:")
        print(f"   Private: {private_file}")
        print(f"   Public:  {public_file}")

def main():
    parser = argparse.ArgumentParser(
        description="🔐 Secure Encryption/Decryption CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s encrypt secret.txt secret.enc
  %(prog)s decrypt secret.enc secret_decrypted.txt  
  %(prog)s genkey my_private.pem my_public.pem
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Encrypt command
    enc_parser = subparsers.add_parser('encrypt', help='Encrypt file')
    enc_parser.add_argument('input', help='Input file to encrypt')
    enc_parser.add_argument('output', help='Output encrypted file')
    
    # Decrypt command
    dec_parser = subparsers.add_parser('decrypt', help='Decrypt file')
    dec_parser.add_argument('input', help='Input encrypted file')
    dec_parser.add_argument('output', help='Output decrypted file')
    
    # Generate keypair
    key_parser = subparsers.add_parser('genkey', help='Generate RSA keypair')
    key_parser.add_argument('private', help='Private key output file')
    key_parser.add_argument('public', help='Public key output file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    crypto = SecureCryptoCLI()
    
    if args.command == 'encrypt':
        password = getpass.getpass("Enter encryption password: ")
        crypto.encrypt_file(args.input, args.output, password)
        
    elif args.command == 'decrypt':
        password = getpass.getpass("Enter decryption password: ")
        crypto.decrypt_file(args.input, args.output, password)
        
    elif args.command == 'genkey':
        crypto.generate_keypair(args.private, args.public)

if __name__ == "__main__":
    main()
