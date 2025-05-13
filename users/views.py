from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .models import EncryptedData, EncryptedMessage
from .serializers import UserSerializer, UserCreateSerializer, EncryptedDataSerializer, MessageSerializer, MessageDecryptSerializer
from .utils import E2EEncryption
from cryptography.fernet import Fernet
import hashlib
import base64

User = get_user_model()

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def get_permissions(self):
        if self.action in ['create', 'generate_keys', 'recover_keys']:
            return [permissions.AllowAny()]
        return super().get_permissions()

    @action(detail=False, methods=['get'])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def generate_keys(self, request):
        """生成用户的密钥对"""
        try:
            # 获取哈希后的密码
            hashed_password = request.data.get('hashed_password')
            if not hashed_password:
                return Response({'error': '需要提供哈希后的密码'}, status=status.HTTP_400_BAD_REQUEST)
            
            # 生成密钥对
            key = Fernet.generate_key()
            f = Fernet(key)
            
            # 生成公钥和私钥
            public_key = key.decode()
            private_key = Fernet.generate_key().decode()
            
            # 使用哈希后的密码加密私钥
            # 将哈希密码转换为Fernet可用的格式
            key_bytes = hashlib.sha256(hashed_password.encode()).digest()
            f2 = Fernet(base64.urlsafe_b64encode(key_bytes))
            encrypted_private_key = f2.encrypt(private_key.encode()).decode()
            
            # 保存到用户模型
            user = request.user
            user.public_key = public_key
            user.encrypted_private_key = encrypted_private_key
            user.save()
            
            return Response({
                'message': '密钥对生成成功',
                'public_key': public_key,
                'private_key': private_key  # 这个私钥只会返回一次，请妥善保存
            })
        except Exception as e:
            return Response({
                'error': f'生成密钥对失败: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def recover_keys(self, request):
        """恢复用户的密钥对"""
        try:
            # 获取哈希后的密码
            hashed_password = request.data.get('hashed_password')
            if not hashed_password:
                return Response({'error': '需要提供哈希后的密码'}, status=status.HTTP_400_BAD_REQUEST)
                
            user = request.user
            if not user.encrypted_private_key:
                return Response({'error': '没有找到加密的私钥'}, status=status.HTTP_400_BAD_REQUEST)
                
            # 使用哈希后的密码解密私钥
            key_bytes = hashlib.sha256(hashed_password.encode()).digest()
            f = Fernet(base64.urlsafe_b64encode(key_bytes))
            private_key = f.decrypt(user.encrypted_private_key.encode()).decode()
            
            return Response({
                'message': '密钥恢复成功',
                'public_key': user.public_key,
                'private_key': private_key
            })
        except Exception as e:
            return Response({
                'error': f'密钥恢复失败: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def upload_avatar(self, request):
        if 'avatar' not in request.FILES:
            return Response({'error': '请上传头像'}, status=status.HTTP_400_BAD_REQUEST)
        
        request.user.avatar = request.FILES['avatar']
        request.user.save()
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

class EncryptedDataViewSet(viewsets.ModelViewSet):
    serializer_class = EncryptedDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EncryptedData.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class MessageViewSet(viewsets.ModelViewSet):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return EncryptedMessage.objects.filter(
            receiver=user
        ).select_related('sender', 'receiver')

    def get_serializer_class(self):
        if self.action == 'retrieve' or self.action == 'list':
            return MessageDecryptSerializer
        return MessageSerializer

    @action(detail=False, methods=['post'])
    def send(self, request):
        """发送加密消息"""
        # 生成对称密钥
        symmetric_key = Fernet.generate_key()
        f = Fernet(symmetric_key)
        
        # 加密消息内容
        content = request.data.get('encrypted_content')
        encrypted_content = f.encrypt(content.encode()).decode()
        
        # 使用接收者的公钥加密对称密钥
        receiver = User.objects.get(id=request.data.get('receiver'))
        if not receiver.public_key:
            return Response({'error': '接收者没有公钥'}, status=status.HTTP_400_BAD_REQUEST)
            
        # 使用接收者的公钥加密对称密钥
        f2 = Fernet(receiver.public_key.encode())
        encrypted_symmetric_key = f2.encrypt(symmetric_key).decode()
        
        # 创建消息
        message_data = {
            'receiver': receiver.id,
            'encrypted_content': encrypted_content,
            'encrypted_symmetric_key': encrypted_symmetric_key
        }
        
        serializer = self.get_serializer(data=message_data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def sent(self, request):
        """获取已发送的消息"""
        messages = EncryptedMessage.objects.filter(
            sender=request.user
        ).select_related('sender', 'receiver')
        serializer = MessageDecryptSerializer(messages, many=True, context={'request': request})
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def received(self, request):
        """获取收到的消息"""
        messages = EncryptedMessage.objects.filter(
            receiver=request.user
        ).select_related('sender', 'receiver')
        serializer = MessageDecryptSerializer(messages, many=True, context={'request': request})
        return Response(serializer.data)