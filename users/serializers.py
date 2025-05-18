from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import EncryptedData, EncryptedMessage
from cryptography.fernet import Fernet
from django.conf import settings

User = get_user_model()

class EncryptedField(serializers.CharField):
    """加密字段"""
    def to_representation(self, value):
        """解密数据"""
        if not value:
            return value
        try:
            f = Fernet(settings.ENCRYPTION_KEY)
            return f.decrypt(value.encode()).decode()
        except:
            return value

    def to_internal_value(self, data):
        """加密数据"""
        if not data:
            return data
        f = Fernet(settings.ENCRYPTION_KEY)
        return f.encrypt(data.encode()).decode()

class UserSerializer(serializers.ModelSerializer):
    # 需要加密的字段
    phone = EncryptedField(required=False)
    bio = EncryptedField(required=False)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'avatar', 'phone', 'bio', 'public_key', 'last_login', 'date_joined')
        read_only_fields = ('last_login', 'date_joined')

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    phone = EncryptedField(required=False)
    bio = EncryptedField(required=False)
    public_key = serializers.CharField(required=False)
    encrypted_private_key = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'phone', 'bio', 'public_key', 'encrypted_private_key')

    def create(self, validated_data):
        phone = validated_data.get('phone')
        if phone and not str(phone).startswith('gAAAAA'):
            f = Fernet(settings.ENCRYPTION_KEY)
            validated_data['phone'] = f.encrypt(phone.encode()).decode()
        bio = validated_data.get('bio')
        if bio and not str(bio).startswith('gAAAAA'):
            f = Fernet(settings.ENCRYPTION_KEY)
            validated_data['bio'] = f.encrypt(bio.encode()).decode()
        email = validated_data.get('email')
        if email and not str(email).startswith('gAAAAA'):
            f = Fernet(settings.ENCRYPTION_KEY)
            validated_data['email'] = f.encrypt(email.encode()).decode()
        user = User.objects.create_user(**validated_data)
        return user

class EncryptedDataSerializer(serializers.ModelSerializer):
    value = EncryptedField(write_only=True)
    encrypted_value = EncryptedField(read_only=True)

    class Meta:
        model = EncryptedData
        fields = ('id', 'key', 'value', 'encrypted_value', 'created_at', 'updated_at')
        read_only_fields = ('created_at', 'updated_at')

    def create(self, validated_data):
        value = validated_data.pop('value')
        instance = super().create(validated_data)
        instance.encrypted_value = value  # 这里会自动加密
        instance.save()
        return instance 

class MessageSerializer(serializers.ModelSerializer):
    encrypted_content = EncryptedField()
    
    class Meta:
        model = EncryptedMessage
        fields = ('id', 'sender', 'receiver', 'encrypted_content', 'encrypted_symmetric_key', 'created_at')
        read_only_fields = ('sender', 'created_at')

    def create(self, validated_data):
        validated_data['sender'] = self.context['request'].user
        return super().create(validated_data)

class MessageDecryptSerializer(serializers.ModelSerializer):
    encrypted_content = EncryptedField()
    sender_username = serializers.CharField(source='sender.username', read_only=True)
    receiver_username = serializers.CharField(source='receiver.username', read_only=True)
    
    class Meta:
        model = EncryptedMessage
        fields = ('id', 'sender', 'sender_username', 'receiver', 'receiver_username', 'encrypted_content', 'created_at')
        read_only_fields = ('sender', 'receiver', 'created_at') 