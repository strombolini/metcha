from flask import Flask, request, redirect, render_template, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from flask import current_app
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///metcha.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from flask_login import UserMixin

class User(db.Model, UserMixin):  
    email = db.Column(db.String(120), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    trust_score = db.Column(db.Float, default=0.5)
    verification_key = db.Column(db.String(100), nullable=True)
    key_expiry = db.Column(db.DateTime, nullable=True)
    ...

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email
    
    def is_active(self):
        """True, as all users are active in this simple case."""
        return True
    
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    target_user_id = db.Column(db.String(120), db.ForeignKey('user.email'))
    answers = db.relationship('Answer', backref='question', lazy='dynamic',
                              foreign_keys='[Answer.question_id]', cascade="all, delete-orphan")
    correct_answer_id = db.Column(db.Integer, db.ForeignKey('answer.id'), nullable=True)
    correct_answer = db.relationship('Answer', foreign_keys=[correct_answer_id], post_update=True, uselist=False, lazy='joined')
    answered = db.Column(db.Boolean, default=False, nullable=False)  # assuming you need to track if answered


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    is_correct = db.Column(db.Boolean, default=False, nullable=False)  # Indicates if the answer is correct


class VerificationKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(120), db.ForeignKey('user.email'), nullable=False)
    key = db.Column(db.String(100), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    
    def generate_key(self):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        key = s.dumps(self.user_id, salt='verification-key')
        print(f"Generated key: {key} at {datetime.datetime.now()}")
        return key

    @staticmethod
    def verify_key(key):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(key, salt='verification-key', max_age=60)
            print(f"Verified key: {key} at {datetime.datetime.now()} for user {user_id}")
            return user_id
        except Exception as e:
            print(f"Verification error: {e} at {datetime.datetime.now()}")
            return None


@login_manager.user_loader
def load_user(user_email):
    return User.query.get(user_email)

@app.route('/')
def home():
    users = User.query.all()
    return render_template('home.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('profile'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/verify_key', methods=['GET', 'POST'])
def verify_key():
    message = None  # Initialize message to None
    if request.method == 'POST':
        user_key = request.form['key']
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(user_key, salt='verification-key', max_age=60)
            message = f"Verified key: {user_key} at {datetime.datetime.now()} for user {user_id}"
            return render_template('verification_result.html', message=message, user_id=user_id)
        except Exception as e:
            message = f"Verification error: {e} at {datetime.datetime.now()}"
            return render_template('verification_result.html', message=message, user_id=None)
    return render_template('verify_key.html', message=message)


@app.route('/submit_question', methods=['POST'])
@login_required
def submit_question():
    target_email = request.form['target_email']
    content = request.form['content']
    answers = request.form['answers'].split(',')
    correct_index = int(request.form['correct_index'])

    target_user = User.query.filter_by(email=target_email).first()
    if not target_user:
        flash('No user with that email exists.')
        return redirect(url_for('profile'))

    new_question = Question(content=content, target_user_id=target_email)
    db.session.add(new_question)
    db.session.flush()  # Ensures new_question.id is available

    for index, answer_content in enumerate(answers):
        new_answer = Answer(
            content=answer_content.strip(),
            question_id=new_question.id,
            is_correct=(index == correct_index)  # Set true if this is the correct answer
        )
        db.session.add(new_answer)

    db.session.commit()
    flash('Question submitted successfully!')
    return redirect(url_for('profile'))

@app.route('/submit_answer/<int:answer_id>', methods=['POST'])
@login_required
def submit_answer(answer_id):
    answer = Answer.query.get(answer_id)
    if answer.is_correct:
        flash("Correct answer! Generating your key...")
        # Generate the key and store it in the user model
        user = current_user
        user.verification_key = VerificationKey().generate_key()
        user.key_expiry = datetime.datetime.now() + datetime.timedelta(minutes=1)
        db.session.commit()
        return redirect(url_for('profile'))
    else:
        flash("Incorrect answer, try again.")
        return redirect(url_for('profile'))
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(email=email).first():
            flash('Email already in use.')
            return redirect(url_for('signup'))
        new_user = User(email=email, name=name, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
    user = current_user
    key_valid = False
    if user.verification_key and user.key_expiry > datetime.datetime.now():
        key_valid = True
    
    questions = Question.query.filter_by(target_user_id=user.email).all()
    return render_template('profile.html', name=user.name, questions=questions, key=user.verification_key if key_valid else None, expiry=user.key_expiry if key_valid else None)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
