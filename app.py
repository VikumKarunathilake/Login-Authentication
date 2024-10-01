from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
import os
from datetime import timedelta
from datetime import timedelta

app = Flask(__name__)

# Configuring the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'ad167372e8cd9f276998fa670e49c67d88faf1d77c20a98f'
# Create a serializer for generating and validating tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize database and migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.your-email-provider.com'  # e.g., smtp.gmail.com
app.config['MAIL_PORT'] = 587  # For TLS
app.config['MAIL_USE_TLS'] = True  # Use TLS
app.config['MAIL_USE_SSL'] = False  # Use SSL
app.config['MAIL_USERNAME'] = 'your-email@example.com'  # Your email address
app.config['MAIL_PASSWORD'] = 'your-email-password'  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'  # Default sender

mail = Mail(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        # Check if the username or email already exists
        existing_user_by_username = User.query.filter_by(username=username).first()
        existing_user_by_email = User.query.filter_by(email=email).first()

        if existing_user_by_username:
            flash('Username already exists. Please choose another one.', 'danger')
        elif existing_user_by_email:
            flash('Email already registered. Please use a different email.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        else:
            # Hash the password using 'pbkdf2:sha256'
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Fetch the user from the database based on the provided email
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Set the session with the user's username or any other detail
            session['username'] = user.username
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('dashboard'))

# Dashboard Route
@app.route('/')
def dashboard():
    username = session.get('username')  # Check if the user is logged in
    app.permanent_session_lifetime = timedelta(minutes=30)
    return render_template('index.html', username=username)

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Find the user by email
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a secure token for password reset
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Simulate sending the reset link (Replace with actual email sending)
            print(f'Reset link: {reset_url}')
            
            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('No account with that email found.', 'danger')

    return render_template('forgot_password.html')

# Password Reset Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Validate the token (valid for 3600 seconds = 1 hour)
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirmPassword']
        
        if new_password == confirm_password:
            # Update user's password
            user = User.query.filter_by(email=email).first()
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.password = hashed_password
            db.session.commit()
            
            flash('Your password has been updated. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match. Please try again.', 'danger')

    return render_template('reset_password.html')

# Main
if __name__ == '__main__':
    app.run(debug=True)
