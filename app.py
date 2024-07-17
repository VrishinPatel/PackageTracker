import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packages.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    google_sheet_id = db.Column(db.String(100), nullable=False)
    packages = db.relationship('Package', backref='club', lazy=True)

class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_number = db.Column(db.String(100), nullable=False, unique=True)
    status = db.Column(db.String(100), nullable=False)
    last_update = db.Column(db.String(100), nullable=False)
    user_notifications = db.Column(db.Boolean, default=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)

# Creating an application context
with app.app_context():
    db.create_all()
    # Add initial clubs
    club_names = [
        'Badminton', 'Ballroom Dance', 'Barbell', 'Baseball', 'Basketball - Men', 'Basketball - Women',
        'Black Belt', 'Boxing', 'Brazilian Jiu-Jitsu', 'Climbing', 'Crew - Men', 'Crew - Women', 'Cricket', 'Cycling', 
        'Dodgeball', 'Equestrian', 'Fencing', 'Field Hockey', 'Figure Skating', 'Flag Football', 'Golf', 
        'Gymnastics', 'Ice Hockey D2 - Men', 'Ice Hockey - Women', 'Lacrosse - Men', 'Lacrosse - Women', 'MSOA', 
        'Paintball', 'Racquetball', 'Roundnet (Spikeball)', 'Rugby - Men', 'Rugby - Women', 'Running', 'Sailing', 
        'Soccer - Men', 'Soccer - Women', 'Softball', 'Swim-good', 'Table Tennis', 'Tennis', 'Triathlon', 
        'Ultimate - Men', 'Ultimate - Women', 'Volleyball - Men', 'Volleyball - Women', 'Water Polo', 'Wrestling', 'Wushu'
    ]
    for name in club_names:
        if not Club.query.filter_by(name=name).first():
            new_club = Club(name=name, user_id=1, google_sheet_id='')
            db.session.add(new_club)
    db.session.commit()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        is_admin = 'is_admin' in request.form
        user = User(username=username, password=password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_admin:
        selected_club_id = request.form.get('club_filter')
        packages = Package.query.filter_by(club_id=selected_club_id).all() if selected_club_id else Package.query.all()
        clubs = Club.query.all()
        return render_template('dashboard_admin.html', packages=packages, clubs=clubs, selected_club_id=selected_club_id)
    else:
        club = Club.query.filter_by(user_id=current_user.id).first()
        packages = Package.query.filter_by(club_id=club.id).all() if club else []
        return render_template('dashboard_club.html', packages=packages, club=club)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/track_package', methods=['GET'])
@login_required
def track_package():
    tracking_number = request.args.get('tracking_number')
    package = Package.query.filter_by(tracking_number=tracking_number).first()
    if package:
        return jsonify({'tracking_number': package.tracking_number, 'status': package.status, 'last_update': package.last_update, 'notifications': package.user_notifications})
    else:
        return jsonify({'error': 'Package not found'}), 404

@app.route('/subscribe_notifications', methods=['POST'])
@login_required
def subscribe_notifications():
    data = request.json
    tracking_number = data.get('tracking_number')
    notify = data.get('notify')
    package = Package.query.filter_by(tracking_number=tracking_number).first()
    if package:
        package.user_notifications = notify
        db.session.commit()
        return jsonify({"status": "success", "tracking_number": tracking_number, "notifications": notify})
    else:
        return jsonify({'error': 'Package not found'}), 404

@app.route('/clubs', methods=['GET', 'POST'])
@login_required
def clubs():
    if request.method == 'POST':
        club_name = request.form['club_name']
        google_sheet_id = request.form['google_sheet_id']
        club = Club(name=club_name, user_id=current_user.id, google_sheet_id=google_sheet_id)
        db.session.add(club)
        db.session.commit()
        flash('Club created successfully!', 'success')
    clubs = Club.query.filter_by(user_id=current_user.id).all()
    return render_template('clubs.html', clubs=clubs)

@app.route('/club/<int:club_id>/packages')
@login_required
def club_packages(club_id):
    club = Club.query.get_or_404(club_id)
    packages = Package.query.filter_by(club_id=club_id).all()
    return render_template('club_packages.html', club=club, packages=packages)

@app.route('/add_package', methods=['POST'])
@login_required
def add_package():
    tracking_number = request.form['tracking_number']
    status = request.form['status']
    last_update = request.form['last_update']
    club_id = request.form['club_id']

    new_package = Package(
        tracking_number=tracking_number,
        status=status,
        last_update=last_update,
        user_notifications=False,
        club_id=club_id
    )

    db.session.add(new_package)
    db.session.commit()
    flash('Package added successfully!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True)
