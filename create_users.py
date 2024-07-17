from database_setup import db, User, bcrypt, app

def create_user(username, password, is_admin=False):
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        create_user('admin', 'admin_password', is_admin=True)  # Replace with actual credentials
        create_user('user', 'user_password')  # Replace with actual credentials
