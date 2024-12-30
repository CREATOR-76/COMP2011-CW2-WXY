from app import app, db
from flask import render_template, flash, redirect, url_for, request, jsonify


from .forms import RegistrationForm, LoginForm, ProfileForm, AddressForm, PasswordForm, ProductForm, CreateForm
from .models import User, Product, Category, UserAction, Order, Address, Cart, CartProducts, OrderStatus, OrderItem
from datetime import datetime, timedelta, date
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import pandas as pd
import logging
from werkzeug.utils import secure_filename
from functools import wraps
from sqlalchemy.sql import func
import os

logger = logging.getLogger(__name__)


# 创建管理员权限检查装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 检查当前用户是否是管理员
        if not current_user.is_admin:
            flash('You do not have permission to view this page.', 'danger')  # 提示信息
            return redirect(url_for('home'))  # 跳转到首页或其他页面
        return f(*args, **kwargs)  # 如果是管理员，则继续执行视图函数

    return decorated_function


def log_user_action(user_id, action, target=None, details=None):
    # 获取用户IP地址和设备信息
    ip_address = request.remote_addr
    user_agent = request.user_agent.string  # 获取浏览器和设备信息

    # 创建一个新的操作日志条目
    user_action = UserAction(
        user_id=user_id,
        action=action,
        target=target,
        details=details,
        ip_address=ip_address,
        device_info=user_agent
    )

    # 将日志条目添加到数据库
    db.session.add(user_action)
    db.session.commit()


@app.route('/admin/user_actions')
def user_actions():
    actions = UserAction.query.order_by(UserAction.timestamp.desc()).all()
    return render_template('admin_user_actions.html', actions=actions)


# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            # 查询数据库，获取该用户名的用户对象
            user = User.query.filter_by(username=username).first()
            # 如果没有找到该用户
            if user is None:
                flash('User not found. Please check your username or register.', 'fail')
                return redirect(url_for('login'))
            # 模拟登录验证
            elif not check_password_hash(user.password, password):
                flash('Invalid password', 'fail')
                return redirect(url_for('login'))
            elif user.is_admin:
                login_user(user)
                return redirect(url_for('index'))
            else:
                # 使用 Flask-Login 登录用户
                login_user(user)
                log_user_action(user.id, 'Login')
                flash('Login successful!', 'success')
                return redirect(url_for('home'))  # 登录成功后跳转到首页

    return render_template('login.html', form=form)


# 注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == "POST":
        if form.validate_on_submit():  # 如果表单验证通过
            # 获取表单数据
            username = form.username.data
            email = form.email.data
            password = form.password.data

            # 检查用户名或邮箱是否已存在
            user = User.query.filter_by(username=username).first()
            if user:
                flash('Username already exists!', 'fail')
                return redirect(url_for('register'))

            email_user = User.query.filter_by(email=email).first()
            if email_user:
                flash('Email is already registered!', 'fail')
                return redirect(url_for('register'))

            # 创建新用户并保存到数据库
            hashed_password = generate_password_hash(password)  # 密码加密
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            log_user_action(new_user.id, 'Register')
            flash('Account created successfully! You can now log in.', 'success')

            # 跳转到登录页面
            return redirect(url_for('login'))

    return render_template('register.html', form=form)


# 退出登录
@app.route('/logout')
@login_required  # 确保用户已登录才能访问
def logout():
    log_user_action(current_user.id, 'logout')
    logout_user()  # 退出登录
    return redirect(url_for('login'))


# 主页
@app.route('/', methods=['GET', 'POST'])
def home():
    init_data()
    product_cake = Product.query.filter_by(id=1).first()
    bread_category = Category.query.filter_by(name="bread").first()
    product_bread = bread_category.products.first()
    pastry_category = Category.query.filter_by(name="pastry").first()
    product_pastry = pastry_category.products.first()
    accessory_category = Category.query.filter_by(name="accessories").first()
    product_accessory = accessory_category.products.first()

    top_products = Product.query.join(Category).filter(Category.name != 'accessories') \
        .order_by(Product.monthly_sale.desc()).limit(4).all()
    number = [1, 2, 3, 4]
    return render_template('Home.html',
                           product_cake=product_cake,
                           product_bread=product_bread,
                           product_pastry=product_pastry,
                           product_accessory=product_accessory,
                           top_products=top_products,
                           number=number
                           )


def init_data():
    try:
        if not Category.query.first():
            # 插入一些初始分类
            category1 = Category(name="cake", description="cakes")
            category2 = Category(name="bread", description="bread")
            category3 = Category(name="pastry", description="pastry")
            category4 = Category(name="accessories", description="accessories")

            db.session.add_all([category1, category2, category3, category4])
            db.session.commit()
            logger.info("Category successfully imported into the database!")

        # 检查是否有产品数据
        if not Product.query.first():
            # 读取Excel文件
            data = pd.read_excel("app/static/data/products.xlsx")
            logger.info(f"Data file loaded successfully: {data.shape[0]} rows found.")

            # 遍历Excel数据并插入数据库
            for _, row in data.iterrows():
                # 创建一个新的Product实例
                product = Product(
                    name=row['name'],
                    size=row['size'],
                    taste=row['taste'],
                    description=row['description'],
                    price=row['price'],
                    monthly_sale=row['monthly_sale'],
                    image_url=row['image_url'],
                    category_id=row['category_id']
                )
                # 添加到session中
                db.session.add(product)

            # 提交数据库操作
            db.session.commit()
            logger.info("product successfully imported into the database!")

        if not User.query.filter_by(username="admin").first():
            password = "adminpass12"
            hashed_password = generate_password_hash(password)
            # 创建一个管理员账户
            admin_user = User(
                username="admin",
                email="admin@example.com",
                password=hashed_password,  # 设置一个安全的默认密码
                is_admin=True  # 设置为管理员
            )
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Admin user created successfully!")

    except Exception as e:
        # 错误记录
        logger.error(f"An error occurred while initializing data: {str(e)}")


# 所有商品
@app.route('/products/<string:category>', methods=['GET', 'POST'])
def products(category='all'):
    # Gets the current page number
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'default')
    product = []
    if sort_by == 'monthly_sale':
        if category == 'all':
            product = Product.query.order_by(Product.monthly_sale.desc()).all()
        elif category == 'cake':
            product = Product.query.filter(Product.category_id == 1).order_by(Product.monthly_sale.desc()).all()
        elif category == 'bread':
            product = Product.query.filter(Product.category_id == 2).order_by(Product.monthly_sale.desc()).all()
        elif category == 'pastry':
            product = Product.query.filter(Product.category_id == 3).order_by(Product.monthly_sale.desc()).all()
        elif category == 'accessory':
            product = Product.query.filter(Product.category_id == 4).order_by(Product.monthly_sale.desc()).all()
    else:
        if category == 'all':
            product = Product.query.order_by(Product.id).all()
        elif category == 'cake':
            product = Product.query.filter(Product.category_id == 1).order_by(Product.id).all()
        elif category == 'bread':
            product = Product.query.filter(Product.category_id == 2).order_by(Product.id).all()
        elif category == 'pastry':
            product = Product.query.filter(Product.category_id == 3).order_by(Product.id).all()
        elif category == 'accessory':
            product = Product.query.filter(Product.category_id == 4).order_by(Product.id).all()

    # Get search content
    search = request.args.get('search', '').strip()
    content = request.args.get('content', '').strip()
    # Determine whether a search has been conducted
    search_action = bool(search or content)
    product = (filter_products(product, content))
    per_page = 15
    total_products = len(product)
    total_pages = max((total_products + per_page - 1) // per_page, 1)
    start = (page - 1) * per_page
    end = start + per_page
    # Gets the current page content
    display_product = product[start:end]

    return render_template('products.html',
                           products=product,
                           display_product=display_product,
                           total_pages=total_pages,
                           current_page=page,
                           sort_by=sort_by,
                           search_action=search_action,
                           category=category)


def filter_products(product, content):
    """
    Filter products based on
    search content.
    """
    # Filter by search content
    if content:
        product = [
            a for a in product
            if (a.name and content.lower() in a.name.lower()) or
               (a.taste and content.lower() in a.taste.lower())
        ]
    return product


@app.route('/products/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and allowed_file(avatar.filename):
                # 安全处理文件名
                filename = secure_filename(avatar.filename)
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                avatar.save(avatar_path)
                current_user.avatar_url = url_for('static', filename='avatar/' + filename)  # 更新头像 URL

        db.session.commit()

        return redirect(url_for('profile'))

    # 获取用户地址
    default_address = Address.query.filter_by(is_default=True, user_id=current_user.id).first()

    return render_template('profile.html',

                           user=current_user,
                           default_address=default_address,
                           )


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/profile/change_name', methods=['GET', 'POST'])
@login_required
def change_name():
    form = ProfileForm(obj=current_user)
    if request.method == 'POST':
        # 修改个人信息
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data

            # 检查用户名和邮箱是否已存在
            existing_username = User.query.filter_by(username=username).first()
            existing_email = User.query.filter_by(email=email).first()

            if existing_username and existing_username.id != current_user.id:
                flash('The username already exists!', 'fail')
                return redirect(url_for('change_name'))

            if existing_email and existing_email.id != current_user.id:
                flash('The email already has the account!', 'fail')
                return redirect(url_for('change_name'))

            current_user.username = username
            current_user.email = email
            db.session.commit()
            flash('Your personal information has been updated!', 'success')

            db.session.commit()

            return redirect(url_for('change_name'))
    return render_template('change_user.html',
                           form=form,
                           user=current_user)


@app.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    password_form = PasswordForm()
    if request.method == 'POST':
        if password_form.validate_on_submit():
            current_password = password_form.current_password.data
            new_password = password_form.new_password.data
            confirm_new_password = password_form.confirm_new_password.data
            # 验证当前密码是否正确
            if not check_password_hash(current_user.password, current_password):
                flash('Incorrect current password!', 'fail')
                return redirect(url_for('change_password'))

            # 检查新密码和确认密码是否匹配
            if new_password != confirm_new_password:
                flash('Passwords do not match!', 'fail')
                return redirect(url_for('change_password'))
            # 更新密码
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your password has been updated!', 'success')

            db.session.commit()

            return redirect(url_for('change_password'))

    return render_template('change_password.html',
                           user=current_user,
                           password_form=password_form)


# 展示所有地址信息
@app.route('/profile/more-addresses')
@login_required
def more_addresses():
    # 跳转到展示所有地址的页面
    all_addresses = Address.query.filter_by(user_id=current_user.id).all()
    return render_template('more_address.html', addresses=all_addresses)


# 添加地址
@app.route('/profile/add-address', methods=['GET', 'POST'])
@login_required
def add_address():
    form = AddressForm()
    if form.validate_on_submit():
        if Address.query.filter_by(user_id=current_user.id, is_default=True).first():
            # 如果已有默认地址，禁止将新地址设为默认地址
            form.is_default.data = False
            flash("There already has the default address!")
        # 创建新地址实例
        new_address = Address(
            user_id=current_user.id,
            contact_name=form.contact_name.data,
            phone_number=form.phone_number.data,
            country=form.country.data,
            city=form.city.data,
            detailed_address=form.detailed_address.data,
            is_default=form.is_default.data
        )
        # 保存到数据库
        db.session.add(new_address)
        db.session.commit()
        flash('Address added successfully!', 'success')
        return redirect(url_for('more_addresses'))  # 假设有地址列表页面

    return render_template('add_address.html', form=form)


@app.route('/edit_address/<int:address_id>', methods=['GET', 'POST'])
@login_required
def edit_address(address_id):
    address = Address.query.filter_by(id=address_id, user_id=current_user.id).first()
    form = AddressForm(obj=address)

    if not address:
        flash('Address not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('more_addresses'))

    if request.method == 'POST':
        if form.validate_on_submit():
            if form.is_default.data :
                # 排除当前编辑的地址，检查其他是否已有默认地址
                existing_default_address = Address.query.filter_by(user_id=current_user.id, is_default=True).first()
                if existing_default_address and existing_default_address.id != address.id:
                    flash(
                        'You can only have one default address. '
                        'Please unset the default on the existing one before setting this as default.',
                        'fail')
                    return redirect(url_for('edit_address', address_id=address.id))
            # 获取表单提交的数据
            address.contact_name = form.contact_name.data
            address.phone_number = form.phone_number.data
            address.country = form.country.data
            address.city = form.city.data
            address.detailed_address = form.detailed_address.data
            address.is_default = form.is_default.data  # 根据复选框选择是否设置为默认

            db.session.commit()
            flash('Address updated successfully!', 'success')
            return redirect(url_for('more_addresses'))

    # GET 请求，展示地址编辑表单
    return render_template('edit_address.html',
                           address=address,
                           form=form)


# 订单
@app.route('/orders/<string:category>', methods=['GET', 'POST'])
@login_required
def orders(category):
    page = request.args.get('page', 1, type=int)
    # 获取用户的订单信息（全部，待付款，待发货，待收货）
    if category == 'UNPAID':
        order = Order.query.filter_by(user_id=current_user.id, status=OrderStatus.UNPAID).all()
    elif category == 'UNSHIPPED':
        order = Order.query.filter_by(user_id=current_user.id, status=OrderStatus.UNSHIPPED).all()
    elif category == 'UNRECEIVED':
        order = Order.query.filter_by(user_id=current_user.id, status=OrderStatus.UNRECEIVED).all()
    else:
        order = Order.query.filter_by(user_id=current_user.id).all()
    per_page = 6
    total_orders = len(order)
    total_pages = max((total_orders + per_page - 1) // per_page, 1)
    start = (page - 1) * per_page
    end = start + per_page
    # Gets the current page content
    display_order = order[start:end]
    if request.method == 'POST':
        order_id = request.form.get("order_id")
        order = Order.query.get_or_404(order_id)
        order.status = OrderStatus.DELIVERED
        db.session.commit()
        flash('Your order has been marked as received!', 'success')
    else:
        flash('This order cannot be updated.', 'danger')

    return render_template('orders.html',
                           orders=order,
                           category=category,
                           total_pages=total_pages,
                           display_order=display_order,
                           current_page=page)


# 添加商品到购物车
@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    product_id = request.form.get('product_id', type=int)
    quantity = request.form.get('quantity', type=int)

    if quantity is None or quantity <= 0 or quantity > 10:  # 限制最大数量为 10
        return jsonify({
            "status": "error",
            "message": "Invalid quantity. Quantity must be between 1 and 10."
        }), 400

    cart_user = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart_user:
        cart_user = Cart(user_id=current_user.id)
        db.session.add(cart_user)
        db.session.commit()

        # 查找或创建购物车中的产品
    cart_product = CartProducts.query.filter_by(cart_id=cart_user.id, product_id=product_id).first()
    if cart_product:
        cart_product.quantity += quantity
    else:
        cart_product = CartProducts(cart_id=cart_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart_product)

    db.session.commit()

    # 记录用户行为
    log_user_action(
        user_id=current_user.id,
        action="add_to_cart",
        target=f"Product ID: {product_id}",
        details=f"Added {cart_product.quantity} of {cart_product.product.name} to cart"
    )

    return jsonify({
        "status": "success",
        "message": "Product added to cart!",
        "product_id": product_id,
        "quantity": cart_product.quantity,
    }), 200


@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    # Fetch the current user's cart
    cart_user = Cart.query.filter_by(user_id=current_user.id).first()

    if not cart_user:
        # If the cart does not exist, create one
        cart_user = Cart(user_id=current_user.id)
        db.session.add(cart_user)
        db.session.commit()
    cart_products = CartProducts.query.filter_by(cart_id=cart_user.id).all()
    products = []
    total_price = 0
    selected_count = 0

    for item in cart_products:
        product = Product.query.get(item.product_id)
        if product:
            products.append({
                "id": product.id,
                "name": product.name,
                "price": product.price,
                "quantity": item.quantity,
                "subtotal": product.price * item.quantity,
                "image_url": product.image_url or "/static/default-product.png",
                "is_chosen": item.is_chosen
            })
            total_price += product.price * item.quantity
    selected_count = sum(1 for item in cart_products if item.is_chosen)
    # Handle form submission (update or delete items)
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        action = request.form.get('action')
        print(request.form)
        if action == 'update':
            cart_item = CartProducts.query.filter_by(cart_id=cart_user.id, product_id=product_id).first()
            new_quantity = int(request.form.get('quantity'))
            if cart_item and new_quantity > 0:
                cart_item.quantity = new_quantity
                db.session.commit()
                log_user_action(
                    user_id=current_user.id,
                    action="Update the number of products to cart",
                    target=f"Product ID: {product_id}",
                    details=f"Changed the number of {cart_item.product.name} with {cart_item.quantity}to cart"
                )
            return redirect(url_for('cart'))
        elif action == 'choose':
            cart_item = CartProducts.query.filter_by(cart_id=cart_user.id, product_id=product_id).first()
            if cart_item:
                cart_item.is_chosen = ('choose_status' in request.form)
                db.session.commit()
            return redirect(url_for('cart'))
        elif action == 'delete':
            cart_item = CartProducts.query.filter_by(cart_id=cart_user.id, product_id=product_id).first()
            if cart_item:
                log_user_action(
                    user_id=current_user.id,
                    action="Delete the product form cart",
                    target=f"Product ID: {product_id}",
                    details=f"Delete the {cart_item.product.name} from cart"
                )
                db.session.delete(cart_item)
                db.session.commit()
            return redirect(url_for('cart'))
        elif action == 'empty':
            cart_item = CartProducts.query.filter_by(cart_id=cart_user.id).all()
            if cart_item:
                for cart_item in cart_item:
                    db.session.delete(cart_item)
                db.session.commit()
                log_user_action(
                    user_id=current_user.id,
                    action="Delete all products from cart",
                    target=f"All products: {cart_item}",
                    details=f"Delete all products from cart"
                )
            return redirect(url_for('cart'))

        if action == 'pay':
            chosen_item = []
            total_price = 0
            cart_products = CartProducts.query.filter_by(cart_id=cart_user.id).all()
            for item in cart_products:
                if item.is_chosen:
                    chosen_item.append(item)
                    total_price += item.product.price * item.quantity
            order = Order(status=OrderStatus.UNPAID, total_price=total_price, user_id=current_user.id)
            db.session.add(order)
            db.session.commit()
            if not chosen_item:
                return "No item is selected for payment", 400
            for item in chosen_item:
                order_item = OrderItem(order_id=order.id, product_id=item.product.id,
                                       quantity=item.quantity, price=item.product.price)
                db.session.add(order_item)

            db.session.commit()
            log_user_action(
                user_id=current_user.id,
                action="create order",
                target=f"Order ID: {order.id}",
                details=f"Buy {chosen_item} product"
            )
            return redirect(url_for('payment', order_id=order.id))
    return render_template('cart.html',
                           products=products,
                           total_price=total_price,
                           cart_products=cart_products,
                           selected_count=selected_count)


# 购买单独的商品
@app.route('/buy_product', methods=['POST'])
@login_required
def buy_product():
    product_id = request.form.get('product_id', type=int)
    quantity = request.form.get('quantity', type=int)
    product = Product.query.get(product_id)
    if not product:
        return "Product not found", 404  # 如果产品不存在，返回 404 错误
        # 检查数量是否有效
    if quantity <= 0:
        return "Invalid quantity", 400
        # 计算价格
    total_price = product.price * quantity
    # 生成订单
    order = Order(user_id=current_user.id, status=OrderStatus.UNPAID, total_price=total_price)
    db.session.add(order)
    db.session.commit()
    # 创建订单项
    order_item = OrderItem(order_id=order.id, product_id=product.id, quantity=quantity, price=total_price)
    db.session.add(order_item)
    db.session.commit()
    log_user_action(
        user_id=current_user.id,
        action="create order",
        target=f"Order ID: {order.id}",
        details=f"Buy {quantity} {product.name} product"
    )
    # 跳转到支付页面
    return redirect(url_for('payment', order_id=order.id))


# 支付页面
@app.route('/payment/<int:order_id>', methods=['GET', 'POST'])
@login_required
def payment(order_id):
    order = Order.query.get(order_id)
    if not order:
        flash("Order not found!", 'fail')
        return redirect(url_for('orders'))
        # 获取用户的所有地址
    default_address = Address.query.filter_by(user_id=current_user.id, is_default=True).first()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'Confirm payment':
            # 获取选择的地址ID（默认为默认地址）
            if not default_address:
                flash('Please select an address to proceed with payment.', 'fail')
                return redirect(url_for('payment', order_id=order_id))
            address_id = default_address.id

            # 获取选中的地址
            selected_address = Address.query.get(address_id)
            if selected_address:
                order.address_id = selected_address.id  # 将地址绑定到订单
                db.session.commit()

            if not order.address_id:
                flash('Please select an address to proceed with payment.', 'fail')
                return redirect(url_for('payment', order_id=order_id))

            # 月销量加一
            order_items = OrderItem.query.filter_by(order_id=order_id).all()
            for order_item in order_items:
                product = Product.query.get(order_item.product_id)
                if product:
                    product.monthly_sale += 1
                    db.session.commit()

            # 更新订单状态
            order.status = OrderStatus.UNSHIPPED
            db.session.commit()

            # 记录用户操作日志
            log_user_action(
                user_id=current_user.id,
                action="Pay an order",
                target=f"Order ID: {order.id}",
                details=f"Pay for {order.total_price}"
            )

            # 重定向到未发货订单页面
            return redirect(url_for('orders', category='UNSHIPPED'))

        else:
            # 如果用户取消支付，重定向到商品页面
            return redirect(url_for('orders', category='UNPAID'))

    return render_template('payment.html',
                           order=order,
                           default_address=default_address)


@app.route('/select_address/<int:order_id>', methods=['GET', 'POST'])
@login_required
def select_address(order_id):
    addresses = Address.query.filter_by(user_id=current_user.id).all()
    order = Order.query.get(order_id)
    if request.method == 'POST':
        action = request.form.get('action')
        address_id = request.form.get('address_id')  # 获取用户选择的地址ID

        # 根据支付操作进行处理
        if action == 'Confirm payment':
            if not address_id:
                flash('Please select an address to proceed with payment.', 'fail')
                return redirect(url_for('select_address', order_id=order_id))
            selected_address = Address.query.get(address_id)
            order.address_id = selected_address.id
            order.status = OrderStatus.UNSHIPPED
            db.session.commit()
            return redirect(url_for('orders', category='UNSHIPPED'))
        elif action == 'Cancel payment':
            # 处理取消支付逻辑
            order.status = OrderStatus.UNPAID
            db.session.commit()
            return redirect(url_for('orders', category='UNPAID'))

    return render_template('address_select.html', order=order, addresses=addresses)


@app.route('/admin/index', methods=['GET', 'POST'])
@login_required
@admin_required
def index():
    current_time = datetime.utcnow().strftime('%I:%M %p')
    product_cake = Product.query.filter_by(id=1).first()
    product_bread = Product.query.filter_by(id=10).first()
    order = Order.query.order_by(Order.order_date.desc()).limit(4).all()

    product_top = Product.query.join(Category).filter(Category.name != 'accessories') \
        .order_by(Product.monthly_sale.desc()).limit(1).first()
    action = UserAction.query.order_by(UserAction.timestamp.desc()).limit(3).all()

    return render_template('index.html',
                           product_cake=product_cake,
                           product_bread=product_bread,
                           product_top=product_top,
                           order=order,
                           action=action,
                           current_time=current_time
                           )


@app.route('/admin/product', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product():
    # Gets the current page number
    page = request.args.get('page', 1, type=int)
    product = Product.query.order_by(Product.id).all()
    # Get search content
    search = request.args.get('search', '').strip()
    content = request.args.get('content', '').strip()
    # Determine whether a search has been conducted
    search_action = bool(search or content)
    product = (filter_products(product, content))
    per_page = 15
    total_products = len(product)
    total_pages = max((total_products + per_page - 1) // per_page, 1)
    start = (page - 1) * per_page
    end = start + per_page
    # Gets the current page content
    display_product = product[start:end]
    if request.method == 'POST':
        product_id = request.form.get("product_id")
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        flash("Product deleted successfully!", "success")
        return redirect(url_for('edit_product'))

    return render_template('edit_product.html',
                           products=product,
                           display_product=display_product,
                           total_pages=total_pages,
                           current_page=page,
                           search_action=search_action)


@app.route('/admin/product/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit(id):
    product = Product.query.get_or_404(id)
    form = ProductForm(obj=product)
    if request.method == 'POST':
        if form.validate_on_submit():
            product.name = form.name.data
            product.size = form.size.data
            product.taste = form.taste.data
            product.description = form.description.data
            product.price = form.price.data
            db.session.commit()
            flash("Product updated successfully!", "success")
            return redirect(url_for('edit', id=product.id))
    return render_template('edit.html',
                           product=product,
                           form=form)


@app.route('/admin/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create():
    form = CreateForm()
    # Get count of assessments
    total_count = Product.query.count()
    if request.method == "POST":
        if form.validate_on_submit():
            # Check for duplicate assessments
            existing_product = Product.query.filter(
                (Product.name == form.name.data)).first()

            if existing_product:
                flash('Product with this name '
                      'already exists!', 'fail')
                return redirect(url_for('create'))
            image_url = form.image_url.data
            image_filename = save_file(image_url)
            # Add the new assessment
            new_product = Product(
                name=form.name.data,
                size=form.size.data,
                taste=form.taste.data,
                description=form.description.data,
                price=form.price.data,
                image_url=image_filename,
                category_id=form.category_id.data
            )
            db.session.add(new_product)
            db.session.commit()
            flash('Submitted successfully!', 'success')
            return redirect(url_for('create'))

    return render_template('create.html',
                           form=form,
                           total_count=total_count,)


def save_file(file):
    if file and allowed_file(file.filename):
        # 生成安全的文件名
        filename = secure_filename(file.filename)

        # 保存到指定路径
        file.save(os.path.join(app.config['PRODUCT_IMG'], filename))

        return url_for('static', filename='new_product/' + filename)  # 返回保存后的文件名

    return None  # 如果文件不合法，则返回 None


@app.route('/admin/order/<string:category>', methods=['GET', 'POST'])
@login_required
@admin_required
def order_admin(category):
    page = request.args.get('page', 1, type=int)
    # 获取用户的订单信息（全部，待付款，待发货，待收货）
    if category == 'UNPAID':
        order = Order.query.filter_by(status=OrderStatus.UNPAID).order_by(Order.order_date.desc()).all()
    elif category == 'UNSHIPPED':
        order = Order.query.filter_by(status=OrderStatus.UNSHIPPED).order_by(Order.order_date.desc()).all()
    elif category == 'UNRECEIVED':
        order = Order.query.filter_by(status=OrderStatus.UNRECEIVED).order_by(Order.order_date.desc()).all()
    else:
        order = Order.query.order_by(Order.order_date.desc()).all()
    per_page = 6
    total_orders = len(order)
    total_pages = max((total_orders + per_page - 1) // per_page, 1)
    start = (page - 1) * per_page
    end = start + per_page
    # Gets the current page content
    display_order = order[start:end]
    if request.method == 'POST':
        order_id = request.form.get("order_id")
        order = Order.query.get(order_id)
        order.status = OrderStatus.UNRECEIVED
        db.session.commit()
        return redirect(url_for('order_admin', category="ALL"))
    return render_template('admin_order.html',
                           orders=order,
                           category=category,
                           total_pages=total_pages,
                           display_order=display_order,
                           current_page=page)


@app.route('/admin/order/<int:order_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def order_detail(order_id):
    order = Order.query.get(order_id)
    return render_template('order_detail.html', order=order)


@app.route('/admin/customers', methods=['GET', 'POST'])
@login_required
@admin_required
def customers():
    user = User.query.all()
    return render_template('Customers.html', user=user)


@app.route('/admin/customers/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def user_action(user_id):
    action = UserAction.query.filter_by(user_id=user_id).order_by(UserAction.timestamp.desc()).all()
    return render_template('user_action.html', action=action)


@app.route('/sales_data', methods=['GET'])
@login_required
@admin_required
def product_sales_data():
    products_sales_data = db.session.query(
        Product.id.label('product_id'),
        Product.name.label('product_name'),
        func.date(Order.order_date).label('date'),
        func.sum(OrderItem.quantity).label('total_sales'),
        func.sum(OrderItem.quantity * OrderItem.price).label('total_profit')
    ).join(OrderItem, Order.id == OrderItem.order_id) \
        .join(Product, Product.id == OrderItem.product_id) \
        .group_by(Product.id, func.date(Order.order_date)) \
        .order_by(Product.id, func.date(Order.order_date)) \
        .all()

    # 将数据按产品组织
    products_data = {}
    for row in products_sales_data:
        product_id = row.product_id
        if product_id not in products_data:
            products_data[product_id] = {
                'product_name': row.product_name,
                'dates': [],
                'sales': [],
                'profits': []
            }
        products_data[product_id]['dates'].append(str(row.date))
        products_data[product_id]['sales'].append(row.total_sales)
        products_data[product_id]['profits'].append(row.total_profit)

    return render_template('data.html', products_data=products_data)