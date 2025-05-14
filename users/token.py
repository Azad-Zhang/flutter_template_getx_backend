from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

class CustomRefreshToken(RefreshToken):
    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        token['token_version'] = user.token_version
        token.access_token['token_version'] = user.token_version
        return token

def get_tokens_for_user(user):
    """生成用户的token对"""
    refresh = CustomRefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    } 