from flask import Flask
from flask_sqlalchemy import SQLAlchemy
#from flask_login import LoginManager


app = Flask(__name__)
app.config['SECRET_KEY'] = 'bb43f19ca8d02c1ad796b50d1e0f4bf4'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'
# login_manager.login_message_category = 'info'

from ecommerce import routes