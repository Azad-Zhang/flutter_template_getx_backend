from rest_framework.views import exception_handler
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from .utils import APIResponse

def custom_exception_handler(exc, context):
    """自定义异常处理器"""
    # 首先调用DRF默认的异常处理
    response = exception_handler(exc, context)

    # 处理JWT相关异常
    if isinstance(exc, (TokenError, InvalidToken)):
        if hasattr(exc, 'detail'):
            message = exc.detail
        else:
            message = str(exc)
        return APIResponse.unauthorized(message=message)

    # 如果response为None，说明是未处理的异常
    if response is None:
        return APIResponse.server_error(message=str(exc))

    # 处理其他DRF异常
    if hasattr(response, 'data'):
        if isinstance(response.data, dict):
            message = response.data.get('detail', str(exc))
        else:
            message = str(response.data)
    else:
        message = str(exc)

    return APIResponse.error(message=message, code=response.status_code) 