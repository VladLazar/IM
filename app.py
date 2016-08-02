from flask import Flask
from flask import Flask, session, request, flash, url_for, redirect, render_template, abort, g
from flask.ext.login import login_user, logout_user, current_user, login_required, LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://balu:Baweelia1@localhost/yournewdb"

db = SQLAlchemy(app)

class User(db.Model):

    __tablename__ = 'user'

    id = db.Column('user_id', db.Integer, primary_key=True)
    username = db.Column('username', db.String(20), unique=True, index=True)
    password = db.Column('password', db.String(10))
    email = db.Column('email', db.String(50), unique=True, index=True)
    online = db.Column('online', db.Boolean)

    def __init__(self, username, password, email, online):
        self.username = username
        self.password = password
        self.email = email
        self.online = online

    def is_active(self):
        """All users are active"""
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        """Return True if user is authenticated"""
        return self.authenticated

    def is_anonymous(self):
        """False, anonymous users not supported"""
        return False

    def __repr__(self):
        return '<User %r>' % (self.username)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    user = User(request.form['username'], request.form['password'], request.form['email'])
    db.session.add(user)
    db.session.commit()
    flash('User succesfully registered')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    password = request.form['password']
    registered_user = User.query.filter_by(username=username, password=password).first()
    if registered_user is None:
        flash('Username or password is invalid!')
        return redirect(url_for('login'))
    login_user(registered_user)
    flash('Logged in successfully!')
    registered_user.online = True
    return redirect(url_for('index'))

@app.before_request
def before_request():
    g.user = current_user

@app.route('/logout')
def logout():
    g.user.online = False
    logout_user()
    return render_template('logout.html')

