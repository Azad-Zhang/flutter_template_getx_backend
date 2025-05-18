from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, EncryptedDataViewSet, MessageViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'encrypted-data', EncryptedDataViewSet, basename='encrypted-data')
router.register(r'messages', MessageViewSet, basename='messages')

urlpatterns = [
    path('', include(router.urls)),
]