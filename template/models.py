from django.db import models
from django.utils import timezone

class Template(models.Model):
    """模板模型"""
    name = models.CharField('模板名称', max_length=100)
    description = models.TextField('模板描述', blank=True)
    content = models.TextField('模板内容')
    created_at = models.DateTimeField('创建时间', default=timezone.now)
    updated_at = models.DateTimeField('更新时间', auto_now=True)
    is_active = models.BooleanField('是否启用', default=True)

    class Meta:
        verbose_name = '模板'
        verbose_name_plural = '模板'
        ordering = ['-created_at']

    def __str__(self):
        return self.name

class TemplateCategory(models.Model):
    """模板分类"""
    name = models.CharField('分类名称', max_length=50)
    description = models.TextField('分类描述', blank=True)
    created_at = models.DateTimeField('创建时间', default=timezone.now)

    class Meta:
        verbose_name = '模板分类'
        verbose_name_plural = '模板分类'
        ordering = ['name']

    def __str__(self):
        return self.name
