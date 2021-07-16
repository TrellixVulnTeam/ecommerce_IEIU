from datetime import datetime
from enum import unique
from operator import truediv
from ecommerce import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    admin = db.Column(db.Boolean)

    def __repr__(self):
        return f"User('{self.name}', '{self.username}, '{self.admin}')"

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(255), nullable=False)
    products = db.relationship('Products', backref='products', lazy=True)

    def __repr__(self):
        return f"Category('{self.id}', '{self.name}', '{self.products}')"


class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"Product('{self.id}', '{self.name}', '{self.category}', '{self.description}', '{self.price}')"
