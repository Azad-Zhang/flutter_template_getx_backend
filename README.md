# Django Backend Template

这是一个基于Django的后端项目模板。

## 环境要求

- Python 3.13+
- Django 5.2+
- Django REST framework
- django-cors-headers

## 安装步骤

1. 创建并激活虚拟环境：
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
.\venv\Scripts\activate  # Windows
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 运行数据库迁移：
```bash
python manage.py migrate
```

4. 启动开发服务器：
```bash
python manage.py runserver
```

## 项目结构

```
backend/
├── manage.py
├── requirements.txt
├── backend/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── README.md
``` 