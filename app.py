from flask import Flask
from flask_bcrypt import Bcrypt
from flask import Flask, session, request, flash, url_for, redirect, render_template, abort, g
from flask_login import login_user, logout_user, current_user, login_required, LoginManager
from flask_sqlalchemy import SQLAlchemy
import os
from forms import LoginForm, RegisterForm
from flask import json
import jsonpickle


app = Flask(__name__)
app.config['DEBUG'] = True
app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://balu:Baweelia1@localhost/yournewdb"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import User, Conversation, Message, db


@app.route('/')
@login_required
def index():
    authenticated_users = User.query.filter_by(authenticated=True).all()
    return render_template('index.html', authenticated_users=authenticated_users)


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=['GET'])
def register_get():
    form = RegisterForm()
    return render_template('register.html', form=form)


@app.route('/register', methods=['POST'])
def register_post():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = bcrypt.generate_password_hash(form.password.data)
        email = form.email.data
        user = User(username, password, email, False)
        db.session.add(user)
        db.session.commit()
        flash('User successfully registered')
        return redirect(url_for('login_get'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET'])
def login_get():
    form = LoginForm()
    if request.method == 'GET':
        return render_template('login.html', form=form)


@app.route('/login', methods=['POST'])
def login_post():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user)
                flash('Logged in successfully!')
                return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/conversation/<partner_username>')
def conversation(partner_username):
    found = False
    partner_user = User.query.filter_by(username=partner_username).first()
    all_conversations = Conversation.query.all()
    if all_conversations:
        for current in all_conversations:
            users_in_current = current.users
            # If the users are alone in the conversation
            if (current_user in users_in_current) and (partner_user in users_in_current) and len(users_in_current) <= 2:
                found = True
                return render_template('chat.html', conversation_id=current.id,
                                       username=current_user.username, other_user=partner_username)
    if not found:
        print partner_user
        print current_user
        new_convo = Conversation()
        new_convo.users.append(current_user)
        new_convo.users.append(partner_user)
        db.session.add(new_convo)
        db.session.commit()
        return render_template('chat.html', conversation_id=new_convo.id,
                               username=current_user.username, other_user=partner_username)


@app.route('/api/get_users', methods=['GET'])
def get_users():
    authenticated_users = User.query.filter_by(authenticated=True).all()
    return jsonpickle.encode(authenticated_users)


@app.route('/api/conversation/<int:conversation_id>', methods=['POST', 'GET'])
def get_and_post_conversation(conversation_id):
    current_conversation = Conversation.query.filter_by(id=conversation_id).first()
    if request.method == 'POST':
        new_message = Message(request.json['message'], request.json['timestamp'], request.json['sender'])
        current_conversation.messages.append(new_message)
        db.session.add(new_message)
        db.session.commit()
        return request.json['message']
    elif request.method == 'GET':
        passed_list = []
        for msg in current_conversation.messages:
            passed_list.append(msg)
        return jsonpickle.encode(passed_list)


@app.before_request
def before_request():
    g.user = current_user


@app.route('/logout')
def logout():
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    return render_template('logout.html')
