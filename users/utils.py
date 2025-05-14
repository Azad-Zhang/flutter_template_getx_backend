from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os
from rest_framework.response import Response
from rest_framework import status

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

class APIResponse:
    """统一API响应格式封装"""
    
    @staticmethod
    def success(data=None, message="操作成功", code=200):
        """成功响应"""
        return Response({
            "code": code,
            "message": message,
            "data": data
        }, status=status.HTTP_200_OK)

    @staticmethod
    def error(message="操作失败", code=400, data=None):
        """错误响应"""
        return Response({
            "code": code,
            "message": message,
            "data": data
        }, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def unauthorized(message="未授权", code=401, data=None):
        """未授权响应"""
        return Response({
            "code": code,
            "message": message,
            "data": data
        }, status=status.HTTP_401_UNAUTHORIZED)

    @staticmethod
    def forbidden(message="禁止访问", code=403, data=None):
        """禁止访问响应"""
        return Response({
            "code": code,
            "message": message,
            "data": data
        }, status=status.HTTP_403_FORBIDDEN)

    @staticmethod
    def not_found(message="资源不存在", code=404, data=None):
        """资源不存在响应"""
        return Response({
            "code": code,
            "message": message,
            "data": data
        }, status=status.HTTP_404_NOT_FOUND)

    @staticmethod
    def server_error(message="服务器错误", code=500, data=None):
        """服务器错误响应"""
        return Response({
            "code": code,
            "message": message,
            "data": data
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 