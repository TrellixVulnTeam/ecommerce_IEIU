import os
#from flask.json import tojson_filter
from ecommerce import app, db
from flask import jsonify, request, Flask, make_response
from ecommerce.models import Category, Products, User
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

def token_required(f):
    @wraps(f)
    def decorate(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'Message': 'Token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'Message': 'Token is invalid'}, 401)
        return f(current_user, *args, **kwargs)
    return decorate


@app.route('/')
def home():
    return ("API")
#User
@app.route('/users', methods=['GET'])
@token_required
def all_users(current_user):
    users = User.query.all()
    data = []
    for user in users:
        user_data = {}
        user_data['name'] = user.name
        user_data['username'] = user.username
        user_data['admin'] = user.admin
        user_data['password'] = user.password
        data.append(user_data)
    return jsonify({'Users': data})

@app.route('/admin/create', methods=['POST'])
def create_admin():
    data = request.get_json()
    username = User.query.filter_by(username=data['username']).first()
    if username:
        return jsonify({'Message': 'Username is already taken'})
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], username=data['username'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message' : 'Admin created'})


@app.route('/user/create', methods=['POST'])
def create_user():
    data = request.get_json()
    username = User.query.filter_by(username=data['username']).first()
    if username:
        return jsonify({'Message': 'Username is already taken'})
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message' : 'User created'})


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify({'Messaage': 'User does not exist'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=120)}, app.config['SECRET_KEY'])
        decoded_token = token.decode('UTF-8')
        return jsonify({'Token': decoded_token})
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})




#Category
@app.route('/category', methods=['GET'])
def categories():
    categories = Category.query.all()
    data = []
    if not categories:
        return jsonify({'Message' : 'No categories found'}, 404)
    for category in categories:
        category_data = {}
        category_data['public_id'] = category.public_id
        category_data['name'] = category.name
        data.append(category_data)
    return jsonify({'Categories' : data})

@app.route('/category/<category_id>/edit', methods=['POST'])
@token_required
def edit_category(current_user, category_id):
    if not current_user.admin:
        return jsonify({'Message': 'Unauthorized action'}, 403)
    data = request.get_json()
    category = Category.query.filter_by(public_id=category_id).first()
    category.name = data['name']
    db.session.commit()
    return jsonify({'Message': 'Category updated'})

@app.route('/category/<category_id>', methods=['GET'])
def category(category_id):
    category = Category.query.filter_by(public_id=category_id).first()
    data = {}
    if not category:
        return jsonify({'Message' : 'Category not found!'}, 404)
    data['category_id'] = category.public_id
    data['name'] = category.name
    return jsonify({'Category' : data})

@app.route("/category/add", methods=['POST'])
@token_required
def add_category(current_user):
    if not current_user.admin:
        return jsonify({'Message': 'Unauthorized action'}, 403)
    data = request.get_json()
    category = Category(public_id=str(uuid.uuid4()), name=data['name'])
    db.session.add(category)
    db.session.commit()
    return jsonify({'Message' : 'Category created'}, 200)


@app.route('/category/<category_id>/delete', methods=['POST'])
@token_required
def delete_category(current_user, category_id):
    if not current_user.admin:
        return jsonify({'Message': 'Unauthorized action'}, 403)
    category = Category.query.filter_by(public_id=category_id).first()
    if not category:
        return jsonify({'Message' : 'Category not found!'})
    db.session.delete(category)
    db.session.commit()
    return jsonify({'Message' : 'Category has been deleted'})




#Products
@app.route('/products', methods=['GET'])
def products():
    data = []
    products = Products.query.order_by(Products.id.desc())
    if not products:
        return jsonify({'Message' : 'No products found'})
    for product in products:
        product_data = {}
        product_data['public_id'] = product.public_id
        product_data['name'] = product.name
        product_data['category_id'] = product.category_id
        product_data['category'] = product.category
        product_data['description'] = product.description
        product_data['price'] = product.price
        data.append(product_data)
    return jsonify({'Products' : data})

@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    product = Products.query.filter_by(public_id=product_id).first()
    data = {}
    data['public_id'] = product.public_id
    data['name'] = product.name
    data['category'] = product.category
    data['description'] = product.description
    data['price'] = product.price
    return jsonify({'Product' : data})


@app.route("/products/add", methods=['POST'])
@token_required
def add_product(current_user):
    if not current_user.admin:
        return jsonify({'Message': 'Unauthorized action'})
    data = request.get_json()
    category_name = Category.query.filter_by(public_id=data['category_id']).first()
    product = Products(public_id=str(uuid.uuid4()), category_id=data['category_id'], name=data['name'], category=category_name.name, description=data['description'], price=data['price'])
    db.session.add(product)
    db.session.commit()
    return jsonify({'Message' : 'Product created'}, 200)

@app.route("/products/<product_id>/delete", methods=['POST'])
@token_required
def delete_product(current_user, product_id):
    if not current_user.admin:
        return jsonify({'Message': 'Unauthorized action'})
    product = Products.query.filter_by(public_id=product_id).first()
    if not product:
        return jsonify({'Message' : 'Product not found!'})
    db.session.delete(product)
    db.session.commit()
    return jsonify({'Message' : 'Product has been deleted'})

@app.route('/products/<product_id>/edit', methods=['POST'])
@token_required
def edit_product(current_user, product_id):
    if not current_user.admin:
        return jsonify({'Message': 'Unauthorized action'}, 403)
    product = Products.query.filter_by(public_id=product_id).first()
    data = request.get_json()
    if 'name' in data:
        product.name = data['name']
    if 'price' in data:
        product.price = data['price']
    if 'description' in data:
        product.description = data['description']
    if 'category_id' in data:
        category = Category.query.filter_by(public_id=data['category_id']).first()
        product.category_id = data['category_id']
        product.category = category.name
    db.session.commit()
    return jsonify({'Message': 'Product updated'})