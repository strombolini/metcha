import csv
from flask import Flask, request, redirect, render_template, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def read_users_from_csv():
    users = {}
    with open('users.csv', mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            users[row['email']] = {'password': row['password'], 'name': row['name']}
    return users

class User(UserMixin):
    def __init__(self, id, name):
        self.id = id
        self.name = name
        
@login_manager.user_loader
def load_user(user_id):
    users = read_users_from_csv()
    user_info = users.get(user_id)
    if user_info:
        return User(user_id, user_info['name'])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    users = read_users_from_csv()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        if user and user['password'] == password:
            user_obj = load_user(username)
            if user_obj:
                login_user(user_obj)
                return redirect(url_for('profile'))
            else:
                flash('User not found.')
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/profile')
@login_required
def profile():
    image_url = url_for('static', filename='welcome_image.jpg')
    return render_template('profile.html', name=current_user.name, image_url=image_url)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
