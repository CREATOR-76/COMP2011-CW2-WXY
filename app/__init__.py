from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from logging_config import configure_logging
import logging
from flask_login import LoginManager


# 配置日志
configure_logging()

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
# Handles all migrations.
migrate = Migrate(app, db)

# 确保日志配置已加载

logger = logging.getLogger(__name__)

# 初始化LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# 指定没有登录的用户访问时重定向到登录页面
login_manager.login_view = 'login'


from .models import User
# 创建用户加载函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


from app import views, models  # noqa:F401, E402
