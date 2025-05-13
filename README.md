# Django 后端项目模板

这是一个基于 Django 和 Django REST framework 的后端项目模板，提供了完整的用户认证、博客功能和文件上传等基础功能。

## 技术栈

- Python 3.x
- Django 5.2+
- Django REST framework 3.14+
- PostgreSQL 13
- Nginx
- Docker & Docker Compose

## 主要功能

- 用户认证与授权（JWT）
- 博客文章管理
- 文件上传与媒体文件处理
- RESTful API
- CORS 支持
- 数据库迁移
- Docker 容器化部署

## 项目结构

```
.
├── backend/          # Django 项目配置
├── blog/            # 博客应用
├── users/           # 用户应用
├── media/           # 媒体文件
├── nginx/           # Nginx 配置
├── template/        # 模板文件
├── manage.py        # Django 管理脚本
├── requirements.txt # 项目依赖
├── Dockerfile       # Docker 构建文件
└── docker-compose.yml # Docker Compose 配置
```

## 本地开发环境设置

1. 克隆项目
```bash
git clone [项目地址]
cd template_backend
```

2. 创建并激活虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
.\venv\Scripts\activate  # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 配置环境变量
创建 `.env` 文件并设置必要的环境变量：
```
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
SECRET_KEY=your_secret_key
```

5. 运行数据库迁移
```bash
python manage.py migrate
```

6. 启动开发服务器
```bash
python manage.py runserver
```

## Docker 部署

1. 构建并启动容器
```bash
docker-compose up --build
```

2. 运行数据库迁移
```bash
docker-compose exec web python manage.py migrate
```

3. 创建超级用户（可选）
```bash
docker-compose exec web python manage.py createsuperuser
```

## API 文档

启动服务器后，访问以下地址查看 API 文档：
- Swagger UI: `http://localhost:8000/api/docs/`
- ReDoc: `http://localhost:8000/api/redoc/`

## 环境变量

项目需要以下环境变量：

- `DB_NAME`: 数据库名称
- `DB_USER`: 数据库用户名
- `DB_PASSWORD`: 数据库密码
- `SECRET_KEY`: Django 密钥
- `DEBUG`: 调试模式（开发环境设为 True，生产环境设为 False）

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

[MIT License](LICENSE) 