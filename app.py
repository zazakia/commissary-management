from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Load configuration from environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///commissary.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize database with all models
with app.app_context():
    try:
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@commissary.com',
                is_admin=True
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists!")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        db.session.rollback()

# Authentication routes
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccountEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # debit/credit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    branch = db.relationship('Branch', backref=db.backref('account_entries', lazy=True))

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    attachment = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    branch = db.relationship('Branch', backref=db.backref('expenses', lazy=True))

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(20), nullable=False)
    cost_price = db.Column(db.Float, nullable=False)
    selling_price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    branch = db.relationship('Branch', backref=db.backref('inventory_items', lazy=True))

@app.route('/')
def index():
    branches = Branch.query.all()
    inventory = Inventory.query.all()
    expenses = Expense.query.all()
    entries = AccountEntry.query.all()
    
    # Calculate total inventory value
    total_inventory_value = sum(item.selling_price * item.quantity for item in inventory)
    
    # Calculate total expenses
    total_expenses = sum(expense.amount for expense in expenses)
    
    # Calculate total account balance
    total_debits = sum(entry.amount for entry in entries if entry.type == 'debit')
    total_credits = sum(entry.amount for entry in entries if entry.type == 'credit')
    account_balance = total_credits - total_debits
    
    return render_template('index.html', 
                         branches=branches,
                         inventory=inventory,
                         expenses=expenses,
                         entries=entries,
                         total_inventory_value=total_inventory_value,
                         total_expenses=total_expenses,
                         account_balance=account_balance)

@app.route('/branches')
@login_required
def branches():
    try:
        branches = Branch.query.all()
        return render_template('branches.html', branches=branches)
    except Exception as e:
        flash('Error loading branches: ' + str(e), 'error')
        return redirect(url_for('index'))

@app.route('/branches/new', methods=['GET', 'POST'])
@login_required
def new_branch():
    if request.method == 'POST':
        try:
            name = request.form['name']
            location = request.form['location']
            branch = Branch(name=name, location=location)
            db.session.add(branch)
            db.session.commit()
            flash('Branch created successfully!', 'success')
            return redirect(url_for('branches'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating branch: ' + str(e), 'error')
    return render_template('new_branch.html')

@app.route('/branches/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_branch(id):
    branch = Branch.query.get_or_404(id)
    if request.method == 'POST':
        try:
            branch.name = request.form['name']
            branch.location = request.form['location']
            db.session.commit()
            flash('Branch updated successfully!', 'success')
            return redirect(url_for('branches'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating branch: ' + str(e), 'error')
    return render_template('edit_branch.html', branch=branch)

@app.route('/branches/<int:id>/delete', methods=['POST'])
@login_required
def delete_branch(id):
    try:
        branch = Branch.query.get_or_404(id)
        db.session.delete(branch)
        db.session.commit()
        flash('Branch deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting branch: ' + str(e), 'error')
    return redirect(url_for('branches'))

@app.route('/accounting')
def accounting():
    entries = AccountEntry.query.order_by(AccountEntry.date.desc()).all()
    branches = Branch.query.all()
    return render_template('accounting.html', entries=entries, branches=branches)

@app.route('/accounting/new', methods=['GET', 'POST'])
def new_account_entry():
    branches = Branch.query.all()
    if request.method == 'POST':
        branch_id = request.form['branch_id']
        date = datetime.strptime(request.form['date'], '%Y-%m-%d')
        description = request.form['description']
        amount = float(request.form['amount'])
        type = request.form['type']
        entry = AccountEntry(
            branch_id=branch_id,
            date=date,
            description=description,
            amount=amount,
            type=type
        )
        db.session.add(entry)
        db.session.commit()
        flash('Account entry created successfully!', 'success')
        return redirect(url_for('accounting'))
    return render_template('new_account_entry.html', branches=branches)

@app.route('/accounting/<int:id>/edit', methods=['GET', 'POST'])
def edit_account_entry(id):
    entry = AccountEntry.query.get_or_404(id)
    branches = Branch.query.all()
    
    if request.method == 'POST':
        entry.branch_id = request.form['branch_id']
        entry.date = datetime.strptime(request.form['date'], '%Y-%m-%d')
        entry.description = request.form['description']
        entry.amount = float(request.form['amount'])
        entry.type = request.form['type']
        db.session.commit()
        flash('Account entry updated successfully!', 'success')
        return redirect(url_for('accounting'))
    
    return render_template('edit_account_entry.html', entry=entry, branches=branches)

@app.route('/accounting/<int:id>/delete', methods=['POST'])
def delete_account_entry(id):
    entry = AccountEntry.query.get_or_404(id)
    db.session.delete(entry)
    db.session.commit()
    flash('Account entry deleted successfully!', 'success')
    return redirect(url_for('accounting'))

@app.route('/expenses')
def expenses():
    expenses = Expense.query.options(db.joinedload(Expense.branch)).order_by(Expense.date.desc()).all()
    branches = Branch.query.all()
    return render_template('expenses.html', expenses=expenses, branches=branches)

@app.route('/expenses/new', methods=['GET', 'POST'])
def new_expense():
    branches = Branch.query.all()
    if request.method == 'POST':
        # Validate form data
        if not all([request.form.get('branch_id'), request.form.get('date'), 
                   request.form.get('category'), request.form.get('amount'), 
                   request.form.get('description')]):
            flash('All fields are required!', 'error')
            return redirect(url_for('new_expense'))
            
        try:
            branch_id = int(request.form['branch_id'])
            date = datetime.strptime(request.form['date'], '%Y-%m-%d')
            amount = float(request.form['amount'])
        except (ValueError, TypeError):
            flash('Invalid input in form fields!', 'error')
            return redirect(url_for('new_expense'))

        category = request.form['category']
        description = request.form['description']
        attachment = request.files.get('attachment')
        
        # Handle attachment
        filename = None
        if attachment:
            # Check file extension
            allowed_extensions = {'jpg', 'jpeg', 'png', 'pdf'}
            file_ext = attachment.filename.rsplit('.', 1)[1].lower() if '.' in attachment.filename else ''
            if file_ext not in allowed_extensions:
                flash('Invalid file type! Only JPG, PNG, and PDF files are allowed.', 'error')
                return redirect(url_for('new_expense'))
                
            # Check file size
            file_size = len(attachment.read())
            attachment.seek(0)  # Reset file pointer
            if file_size > 16 * 1024 * 1024:  # 16MB limit
                flash('File size too large! Maximum allowed size is 16MB.', 'error')
                return redirect(url_for('new_expense'))
                
            filename = secure_filename(attachment.filename)
            attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
        expense = Expense(
            branch_id=branch_id,
            date=date,
            category=category,
            amount=amount,
            description=description,
            attachment=filename
        )
        db.session.add(expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('expenses'))
    
    return render_template('new_expense.html', branches=branches)

@app.route('/expenses/<int:id>/edit', methods=['GET', 'POST'])
def edit_expense(id):
    expense = Expense.query.options(db.joinedload(Expense.branch)).filter_by(id=id).first()
    if not expense:
        flash('Expense not found!', 'error')
        return redirect(url_for('expenses'))
    
    branches = Branch.query.all()
    
    if request.method == 'POST':
        # Validate form data
        if not all([request.form.get('branch_id'), request.form.get('date'), 
                   request.form.get('category'), request.form.get('amount'), 
                   request.form.get('description')]):
            flash('All fields are required!', 'error')
            return redirect(url_for('edit_expense', id=id))
            
        try:
            expense.branch_id = int(request.form['branch_id'])
            expense.date = datetime.strptime(request.form['date'], '%Y-%m-%d')
            expense.amount = float(request.form['amount'])
        except (ValueError, TypeError):
            flash('Invalid input in form fields!', 'error')
            return redirect(url_for('edit_expense', id=id))

        expense.category = request.form['category']
        expense.description = request.form['description']
        
        # Handle new attachment
        attachment = request.files.get('attachment')
        if attachment:
            # Check file extension
            allowed_extensions = {'jpg', 'jpeg', 'png', 'pdf'}
            file_ext = attachment.filename.rsplit('.', 1)[1].lower() if '.' in attachment.filename else ''
            if file_ext not in allowed_extensions:
                flash('Invalid file type! Only JPG, PNG, and PDF files are allowed.', 'error')
                return redirect(url_for('edit_expense', id=id))
                
            # Check file size
            file_size = len(attachment.read())
            attachment.seek(0)  # Reset file pointer
            if file_size > 16 * 1024 * 1024:  # 16MB limit
                flash('File size too large! Maximum allowed size is 16MB.', 'error')
                return redirect(url_for('edit_expense', id=id))
                
            filename = secure_filename(attachment.filename)
            attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            expense.attachment = filename
            
        # Remove attachment if requested
        if 'remove_attachment' in request.form:
            if expense.attachment:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], expense.attachment))
                except OSError:
                    flash('Error removing old attachment!', 'error')
                expense.attachment = None
                
        db.session.commit()
        flash('Expense updated successfully!', 'success')
        return redirect(url_for('expenses'))
    
    return render_template('edit_expense.html', expense=expense, branches=branches)

@app.route('/expenses/<int:id>/delete', methods=['POST'])
def delete_expense(id):
    expense = Expense.query.get_or_404(id)
    if expense.attachment:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], expense.attachment))
    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully!', 'success')
    return redirect(url_for('expenses'))

@app.route('/inventory')
def inventory():
    items = Inventory.query.options(db.joinedload(Inventory.branch)).all()
    branches = Branch.query.all()
    return render_template('inventory.html', items=items, branches=branches)

@app.route('/inventory/new', methods=['GET', 'POST'])
def new_inventory():
    branches = Branch.query.all()
    if request.method == 'POST':
        branch_id = request.form['branch_id']
        product_name = request.form['product_name']
        quantity = int(request.form['quantity'])
        unit = request.form['unit']
        cost_price = float(request.form['cost_price'])
        selling_price = float(request.form['selling_price'])
        
        item = Inventory(
            branch_id=branch_id,
            product_name=product_name,
            quantity=quantity,
            unit=unit,
            cost_price=cost_price,
            selling_price=selling_price
        )
        db.session.add(item)
        db.session.commit()
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('inventory'))
    return render_template('new_inventory.html', branches=branches)

@app.route('/inventory/<int:id>/edit', methods=['GET', 'POST'])
def edit_inventory(id):
    item = Inventory.query.options(db.joinedload(Inventory.branch)).get_or_404(id)
    branches = Branch.query.all()
    
    if request.method == 'POST':
        item.branch_id = request.form['branch_id']
        item.product_name = request.form['product_name']
        item.quantity = int(request.form['quantity'])
        item.unit = request.form['unit']
        item.cost_price = float(request.form['cost_price'])
        item.selling_price = float(request.form['selling_price'])
        db.session.commit()
        flash('Inventory item updated successfully!', 'success')
        return redirect(url_for('inventory'))
    
    return render_template('edit_inventory.html', item=item, branches=branches)

@app.route('/inventory/<int:id>/delete', methods=['POST'])
def delete_inventory(id):
    item = Inventory.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Inventory item deleted successfully!', 'success')
    return redirect(url_for('inventory'))

# Add static route for uploads
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        app.logger.error(f"Error serving file {filename}: {str(e)}")
        flash('Error loading attachment. Please try again.', 'error')
        return redirect(request.referrer or url_for('expenses'))

@app.route('/expense-report')
def expense_report():
    # Get all expenses
    expenses = Expense.query.options(db.joinedload(Expense.branch)).order_by(Expense.date.desc()).all()
    
    # Calculate totals
    total_expenses = sum(expense.amount for expense in expenses)
    expenses_by_category = {}
    expenses_by_branch = {}
    
    # Group expenses by category and branch
    for expense in expenses:
        # Category totals
        if expense.category in expenses_by_category:
            expenses_by_category[expense.category] += expense.amount
        else:
            expenses_by_category[expense.category] = expense.amount
        
        # Branch totals
        if expense.branch.name in expenses_by_branch:
            expenses_by_branch[expense.branch.name] += expense.amount
        else:
            expenses_by_branch[expense.branch.name] = expense.amount
    
    return render_template('expense_report.html',
                         expenses=expenses,
                         total_expenses=total_expenses,
                         expenses_by_category=expenses_by_category.items(),
                         expenses_by_branch=expenses_by_branch.items())

@app.route('/inventory-report')
def inventory_report():
    # Get all inventory items
    inventory = Inventory.query.options(db.joinedload(Inventory.branch)).all()
    
    # Calculate totals
    total_items = len(inventory)
    total_value = sum(item.selling_price * item.quantity for item in inventory)
    
    # Group by branch
    inventory_by_branch = {}
    for item in inventory:
        branch_name = item.branch.name
        if branch_name not in inventory_by_branch:
            inventory_by_branch[branch_name] = {
                'total_items': 0,
                'total_value': 0,
                'items': []
            }
        
        inventory_by_branch[branch_name]['total_items'] += item.quantity
        inventory_by_branch[branch_name]['total_value'] += item.selling_price * item.quantity
        inventory_by_branch[branch_name]['items'].append(item)
    
    # Calculate low stock items (less than 10% of initial quantity)
    low_stock_items = []
    for item in inventory:
        if item.quantity < 10:  # Consider low stock when quantity is less than 10
            low_stock_items.append(item)
    
    return render_template('inventory_report.html',
                         inventory=inventory,
                         total_items=total_items,
                         total_value=total_value,
                         inventory_by_branch=inventory_by_branch.items(),
                         low_stock_items=low_stock_items)

# User Management Routes
@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/new', methods=['GET', 'POST'])
@login_required
def new_user():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_admin = 'is_admin' in request.form
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('new_user'))
            
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('new_user'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('new_user'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('new_user'))
            
        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('User created successfully!', 'success')
        return redirect(url_for('users'))
    
    return render_template('new_user.html')

@app.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        is_admin = 'is_admin' in request.form
        
        if not all([username, email]):
            flash('Username and email are required!', 'error')
            return redirect(url_for('edit_user', id=id))
            
        if User.query.filter_by(username=username).first() and username != user.username:
            flash('Username already exists!', 'error')
            return redirect(url_for('edit_user', id=id))
            
        if User.query.filter_by(email=email).first() and email != user.email:
            flash('Email already registered!', 'error')
            return redirect(url_for('edit_user', id=id))
            
        if new_password and confirm_password:
            if new_password != confirm_password:
                flash('New passwords do not match!', 'error')
                return redirect(url_for('edit_user', id=id))
            user.set_password(new_password)
        
        user.username = username
        user.email = email
        user.is_admin = is_admin
        db.session.commit()
        
        flash('User updated successfully!', 'success')
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/users/<int:id>/delete', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Cannot delete your own account!', 'error')
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
            
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([username, password]):
            flash('Username and password are required!', 'error')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # In a real application, you would send a password reset email here
            flash('If the email exists in our system, you will receive instructions to reset your password.', 'info')
        else:
            flash('If the email exists in our system, you will receive instructions to reset your password.', 'info')
            
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # In a real application, you would verify the token here
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([password, confirm_password]):
            flash('Password and confirmation are required!', 'error')
            return redirect(url_for('reset_password', token=token))
            
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('reset_password', token=token))
            
        # In a real application, you would verify the token and update the password here
        flash('Password has been reset!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Add login_required decorator to protected routes
@app.route('/')
@login_required
def dashboard():
    branches = Branch.query.all()
    inventory = Inventory.query.all()
    expenses = Expense.query.all()
    entries = AccountEntry.query.all()
    
    # Calculate total inventory value
    total_inventory_value = sum(item.selling_price * item.quantity for item in inventory)
    
    # Calculate total expenses
    total_expenses = sum(expense.amount for expense in expenses)
    
    # Calculate total account balance
    total_debits = sum(entry.amount for entry in entries if entry.type == 'debit')
    total_credits = sum(entry.amount for entry in entries if entry.type == 'credit')
    account_balance = total_credits - total_debits
    
    return render_template('index.html', 
                         branches=branches,
                         inventory=inventory,
                         expenses=expenses,
                         entries=entries,
                         total_inventory_value=total_inventory_value,
                         total_expenses=total_expenses,
                         account_balance=account_balance)

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()
        app.run(debug=True)
    except Exception as e:
        print(f"Error starting application: {str(e)}")
        raise
