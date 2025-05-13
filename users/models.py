from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.conf import settings

class User(AbstractUser):
    """自定义用户模型"""
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    bio = models.TextField(null=True, blank=True)
    public_key = models.TextField(null=True, blank=True)  # 用户的公钥
    encrypted_private_key = models.TextField(null=True, blank=True)  # 使用密码加密后的私钥
    last_login_ip = models.GenericIPAddressField('最后登录IP', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', default=timezone.now)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        verbose_name = '用户'
        verbose_name_plural = '用户'
        ordering = ['-date_joined']
        db_table = 'users_user'

    def __str__(self):
        return self.username

class EncryptedData(models.Model):
    """加密数据模型"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='encrypted_data')
    key = models.CharField(max_length=255)
    encrypted_value = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '加密数据'
        verbose_name_plural = '加密数据'
        db_table = 'users_encrypteddata'
        unique_together = ('user', 'key')

class EncryptedMessage(models.Model):
    """端到端加密消息模型"""
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='received_messages')
    encrypted_content = models.TextField()  # 加密后的消息内容
    encrypted_symmetric_key = models.TextField()  # 使用接收者公钥加密的对称密钥
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '加密消息'
        verbose_name_plural = '加密消息'
        db_table = 'users_encryptedmessage'
        ordering = ['-created_at']
