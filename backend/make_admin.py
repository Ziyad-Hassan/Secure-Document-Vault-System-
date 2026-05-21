from app import create_app
from extensions import db
from models.user import User, Role

app = create_app()

with app.app_context():
    admin_role = Role.query.filter_by(name="admin").first()
    if not admin_role:
        admin_role = Role(name="admin")
        db.session.add(admin_role)
        db.session.commit()
        print("Created 'admin' role in database.")

    my_email = "zizo@gmail.com"
    user = User.query.filter_by(email=my_email).first()

    if user:
        user.role_id = admin_role.id
        db.session.commit()
        print(f"✅ Success! User '{user.username}' is now an ADMIN.")
    else:
        print("❌ User not found. Please check the email and make sure you registered first.")