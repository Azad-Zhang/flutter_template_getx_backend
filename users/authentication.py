from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth import get_user_model

User = get_user_model()

class CustomJWTAuthentication(JWTAuthentication):
    def get_validated_token(self, raw_token):
        """
        验证token并检查token_version
        """
        validated_token = super().get_validated_token(raw_token)
        
        # 从token中获取用户ID和token_version
        user_id = validated_token.get('user_id')
        token_version = validated_token.get('token_version')
        
        if not user_id or not token_version:
            raise PermissionDenied('Token无效')
            
        try:
            user = User.objects.get(id=user_id)
            # 检查token_version是否匹配
            if user.token_version != token_version:
                raise PermissionDenied('Token已失效，请重新登录')
        except User.DoesNotExist:
            raise PermissionDenied('用户不存在')
            
        return validated_token

    def authenticate(self, request):
        """重写认证方法，确保在认证时也检查token_version"""
        try:
            return super().authenticate(request)
        except InvalidToken as e:
            raise PermissionDenied(str(e)) 