from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os

class E2EEncryption:
    @staticmethod
    def generate_key_pair():
        """生成RSA密钥对"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # 序列化私钥
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 序列化公钥
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': base64.b64encode(private_pem).decode(),
            'public_key': base64.b64encode(public_pem).decode()
        }

    @staticmethod
    def encrypt_with_public_key(public_key_pem, data):
        """使用公钥加密数据"""
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_pem)
        )
        encrypted = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt_with_private_key(private_key_pem, encrypted_data):
        """使用私钥解密数据"""
        private_key = serialization.load_pem_private_key(
            base64.b64decode(private_key_pem),
            password=None
        )
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    @staticmethod
    def generate_symmetric_key():
        """生成对称加密密钥"""
        return Fernet.generate_key().decode()

    @staticmethod
    def encrypt_symmetric(key, data):
        """使用对称密钥加密数据"""
        f = Fernet(key.encode())
        return f.encrypt(data.encode()).decode()

    @staticmethod
    def decrypt_symmetric(key, encrypted_data):
        """使用对称密钥解密数据"""
        f = Fernet(key.encode())
        return f.decrypt(encrypted_data.encode()).decode() 