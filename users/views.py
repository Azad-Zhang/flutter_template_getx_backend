from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .models import EncryptedData, EncryptedMessage
from .serializers import UserSerializer, UserCreateSerializer, EncryptedDataSerializer, MessageSerializer, MessageDecryptSerializer
from .utils import E2EEncryption, APIResponse
from .token import get_tokens_for_user
from cryptography.fernet import Fernet
import hashlib
import base64
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

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
        if self.action == 'create':
            return [permissions.AllowAny()]
        return super().get_permissions()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return APIResponse.success(
            data=UserSerializer(user).data,
            message='用户注册成功'
        )

    @action(detail=False, methods=['get'])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return APIResponse.success(data=serializer.data)

    @action(detail=False, methods=['post'])
    def generate_keys(self, request):
        """生成用户的密钥对"""
        try:
            # 获取哈希后的密码
            hashed_password = request.data.get('hashed_password')
            if not hashed_password:
                return APIResponse.error(message='需要提供哈希后的密码')
            
            # 生成密钥对
            key = Fernet.generate_key()
            f = Fernet(key)
            
            # 生成公钥和私钥
            public_key = key.decode()
            private_key = Fernet.generate_key().decode()
            
            # 使用哈希后的密码加密私钥
            key_bytes = hashlib.sha256(hashed_password.encode()).digest()
            f2 = Fernet(base64.urlsafe_b64encode(key_bytes))
            encrypted_private_key = f2.encrypt(private_key.encode()).decode()
            
            # 保存到用户模型
            user = request.user
            user.public_key = public_key
            user.encrypted_private_key = encrypted_private_key
            user.save()
            
            return APIResponse.success(data={
                'public_key': public_key,
                'private_key': private_key  # 这个私钥只会返回一次，请妥善保存
            }, message='密钥对生成成功')
        except Exception as e:
            return APIResponse.error(message=f'生成密钥对失败: {str(e)}')

    @action(detail=False, methods=['post'])
    def recover_keys(self, request):
        """恢复用户的密钥对"""
        try:
            # 获取哈希后的密码
            hashed_password = request.data.get('hashed_password')
            if not hashed_password:
                return APIResponse.error(message='需要提供哈希后的密码')
                
            user = request.user
            if not user.encrypted_private_key:
                return APIResponse.error(message='没有找到加密的私钥')
                
            # 使用哈希后的密码解密私钥
            key_bytes = hashlib.sha256(hashed_password.encode()).digest()
            f = Fernet(base64.urlsafe_b64encode(key_bytes))
            private_key = f.decrypt(user.encrypted_private_key.encode()).decode()
            
            return APIResponse.success(data={
                'public_key': user.public_key,
                'private_key': private_key
            }, message='密钥恢复成功')
        except Exception as e:
            return APIResponse.error(message=f'密钥恢复失败: {str(e)}')

    @action(detail=False, methods=['post'])
    def upload_avatar(self, request):
        if 'avatar' not in request.FILES:
            return APIResponse.error(message='请上传头像')
        
        request.user.avatar = request.FILES['avatar']
        request.user.save()
        serializer = self.get_serializer(request.user)
        return APIResponse.success(data=serializer.data, message='头像上传成功')

class EncryptedDataViewSet(viewsets.ModelViewSet):
    serializer_class = EncryptedDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return EncryptedData.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return APIResponse.success(data=serializer.data, message='加密数据创建成功')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(data=serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return APIResponse.success(data=serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return APIResponse.success(data=serializer.data, message='加密数据更新成功')

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return APIResponse.success(message='加密数据删除成功')

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
        try:
            # 生成对称密钥
            symmetric_key = Fernet.generate_key()
            f = Fernet(symmetric_key)
            
            # 加密消息内容
            content = request.data.get('encrypted_content')
            encrypted_content = f.encrypt(content.encode()).decode()
            
            # 使用接收者的公钥加密对称密钥
            receiver = User.objects.get(id=request.data.get('receiver'))
            if not receiver.public_key:
                return APIResponse.error(message='接收者没有公钥')
                
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
            return APIResponse.success(data=serializer.data, message='消息发送成功')
        except User.DoesNotExist:
            return APIResponse.error(message='接收者不存在')
        except Exception as e:
            return APIResponse.error(message=f'发送消息失败: {str(e)}')

    @action(detail=False, methods=['get'])
    def sent(self, request):
        """获取已发送的消息"""
        messages = EncryptedMessage.objects.filter(
            sender=request.user
        ).select_related('sender', 'receiver')
        serializer = MessageDecryptSerializer(messages, many=True, context={'request': request})
        return APIResponse.success(data=serializer.data)

    @action(detail=False, methods=['get'])
    def received(self, request):
        """获取收到的消息"""
        messages = EncryptedMessage.objects.filter(
            receiver=request.user
        ).select_related('sender', 'receiver')
        serializer = MessageDecryptSerializer(messages, many=True, context={'request': request})
        return APIResponse.success(data=serializer.data)

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        try:
            # 先验证用户名和密码
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            # 获取用户并更新token_version
            user = User.objects.get(username=request.data.get('username'))
            user.increment_token_version()
            
            # 使用自定义token生成器生成token
            tokens = get_tokens_for_user(user)
            return APIResponse.success(data=tokens, message='登录成功')
        except TokenError as e:
            return APIResponse.error(message=str(e))
        except User.DoesNotExist:
            return APIResponse.error(message='用户不存在')

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            return APIResponse.success(data=response.data, message='Token刷新成功')
        except TokenError as e:
            return APIResponse.error(message=str(e))