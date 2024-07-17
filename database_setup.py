from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packages.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your secret key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_number = db.Column(db.String(100), nullable=False, unique=True)
    status = db.Column(db.String(100), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Creating an application context
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
