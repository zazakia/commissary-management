from app import app, db, User, Branch, AccountEntry, Expense, Inventory
from datetime import datetime

with app.app_context():
    # Create all tables
    db.create_all()
    
    # Create admin user
    admin_user = User(username='admin', email='admin@example.com', is_admin=True)
    admin_user.set_password('password123')
    db.session.add(admin_user)
    
    # Create test branch
    test_branch = Branch(name='Main Branch', location='Main Location')
    db.session.add(test_branch)
    db.session.commit()  # Commit branch first to get its ID
    
    # Create test account entry
    test_entry = AccountEntry(
        branch_id=test_branch.id,
        date=datetime.now(),
        description='Test Entry',
        amount=1000.00,
        type='credit'
    )
    db.session.add(test_entry)
    
    # Create test expense
    test_expense = Expense(
        branch_id=test_branch.id,
        date=datetime.now(),
        category='Office Supplies',
        amount=150.00,
        description='Test Expense'
    )
    db.session.add(test_expense)
    
    # Create test inventory item
    test_inventory = Inventory(
        branch_id=test_branch.id,
        product_name='Test Product',
        quantity=100,
        unit='pcs',
        cost_price=5.00,
        selling_price=10.00
    )
    db.session.add(test_inventory)
    
    # Commit all remaining changes
    db.session.commit()
    print("Database initialized with test data!")
