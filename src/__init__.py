from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

from .routes import auth, main, inventory, expenses, accounting, users, branches

app.register_blueprint(auth.bp)
app.register_blueprint(main.bp)
app.register_blueprint(inventory.bp)
app.register_blueprint(expenses.bp)
app.register_blueprint(accounting.bp)
app.register_blueprint(users.bp)
app.register_blueprint(branches.bp)

from .models import User, Branch, Inventory, Expense, AccountEntry

db.create_all()
