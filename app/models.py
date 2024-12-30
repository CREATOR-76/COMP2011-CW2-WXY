from app import db
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import Enum
from enum import Enum as PyEnum


class OrderStatus(PyEnum):
    UNPAID = "UNPAID"
    UNSHIPPED = "UNSHIPPED"
    UNRECEIVED = "UNRECEIVED"
    DELIVERED = "DELIVERED"


# 用户
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), index=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    avatar_url = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='user', lazy='dynamic')
    cart = db.relationship('Cart', backref='user', lazy='dynamic')
    addresses = db.relationship('Address', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

    def __init__(self, username, email, password, is_admin):
        self.username = username
        self.email = email
        self.password = password
        self.is_admin = is_admin


# 地址
class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_name = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.Integer, nullable=False)
    country = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    detailed_address = db.Column(db.String(300), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='address', lazy='dynamic')


# 商品
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), index=True, nullable=False)
    size = db.Column(db.String(100), nullable=False)
    taste = db.Column(db.String(100))
    description = db.Column(db.String(800))
    price = db.Column(db.Float, nullable=False)
    monthly_sale = db.Column(db.Integer, nullable=False, default=0)
    image_url = db.Column(db.String(200), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    orders = db.relationship('OrderItem', backref='product', lazy='dynamic', cascade='all, delete', passive_deletes=True)
    cart_items = db.relationship('CartProducts', backref='product', lazy='dynamic', cascade='all, delete', passive_deletes=True)

    def __init__(self, name, size, taste, description, price, image_url, category_id):
        self.name = name
        self.size = size
        self.taste = taste
        self.description = description
        self.price = price
        self.image_url = image_url
        self.category_id = category_id


# 订单
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(Enum(OrderStatus), nullable=False, default=OrderStatus.UNPAID)
    total_price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('OrderItem', backref='order', lazy='dynamic')
    address_id = db.Column(db.Integer, db.ForeignKey('address.id'))


# 订单与产品多对多关系的中介表
class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)


# 分类
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    products = db.relationship('Product', backref='category', lazy='dynamic')


# 购物车
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# 购物车与商品多对多关系
class CartProducts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, default=1)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE'), nullable=False)
    is_chosen = db.Column(db.Boolean, default=False)


# 用户行为
class UserAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 外键，关联到用户表
    action = db.Column(db.String(100), nullable=False)  # 操作类型
    target = db.Column(db.Integer, nullable=True)  # 操作目标ID（例如产品ID）
    details = db.Column(db.JSON, nullable=True)  # 存储操作的详细信息
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # 操作时间
    ip_address = db.Column(db.String(50), nullable=True)  # 用户IP地址
    device_info = db.Column(db.String(255), nullable=True)  # 设备信息（例如浏览器、操作系统等）

    def __init__(self, user_id, action, target=None, details=None, ip_address=None, device_info=None):
        self.user_id = user_id
        self.action = action
        self.target = target
        self.details = details
        self.ip_address = ip_address
        self.device_info = device_info

    def __repr__(self):
        return f'<UserAction {self.action} by user {self.user_id}>'
