import os
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
SQLALCHEMY_TRACK_MODIFICATIONS = True


# 文件上传配置
UPLOAD_FOLDER = os.path.join(basedir, 'app/static/avatar')  # 上传头像的存储路径
PRODUCT_IMG = os.path.join(basedir, 'app/static/new_product')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 设置最大上传文件大小（16MB）


WTF_CSRF_ENABLED = True  # configure CSRF
SECRET_KEY = 'a-very-secret-secret'
