from django.contrib import admin
from .models import Template, TemplateCategory

@admin.register(Template)
class TemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'updated_at', 'is_active')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description', 'content')
    date_hierarchy = 'created_at'

@admin.register(TemplateCategory)
class TemplateCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name', 'description')
