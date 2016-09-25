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

from models import User, Conversation, Message, Invite, db


@app.route('/')
@login_required
def index():
    authenticated_users = User.query.filter_by(authenticated=True).all()
    invites_of_current_user = current_user.invites
    conferences_of_user = Conversation.query.filter(
                        Conversation.users.contains(current_user),
                        Conversation.is_conference == True
                        )
    return render_template('index.html', authenticated_users=authenticated_users, current_username=current_user.username
                           ,invites=invites_of_current_user, conferences=conferences_of_user)


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=['GET'])
def register_get():
    form = RegisterForm()
    return render_template('register.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
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
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
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
    elif request.method == 'GET':
        return render_template('login.html', form=form)


@app.route('/conversation/<partner_username>')
def conversation(partner_username):
    partner_user = User.query.filter_by(username=partner_username).first()
    all_conversations = Conversation.query.all()
    if all_conversations:
        for current in all_conversations:
            users_in_current = current.users
            # If the users are alone in the conversation
            if (current_user in users_in_current) and (partner_user in users_in_current) and len(users_in_current) <= 2:
                return render_template('chat.html', conversation_id=current.id,
                                       username=current_user.username)
    print partner_user
    print current_user
    new_convo = Conversation(is_conference=False)
    new_convo.users.append(current_user)
    new_convo.users.append(partner_user)
    db.session.add(new_convo)
    db.session.commit()
    return render_template('chat.html', conversation_id=new_convo.id,
                           username=current_user.username)


@app.route('/conference/<conference_id>')
def conference(conference_id):
    current_conference = Conversation.query.filter_by(id=conference_id).first()
    return render_template('chat.html', conversation_id=conference_id,
                           username=current_user.username)

@app.route('/api/get_users', methods=['GET'])
def get_users():
    authenticated_users = User.query.filter_by(authenticated=True).all()
    return jsonpickle.encode(authenticated_users)


@app.route('/api/conversation/<int:conversation_id>', methods=['POST', 'GET'])
def get_and_post_conversation(conversation_id):
    current_conversation = Conversation.query.filter_by(id=conversation_id).first()
    if request.method == 'POST':
        new_message = Message(message=request.json['message'], timestamp=request.json['timestamp'], sender=request.json['sender'])
        current_conversation.messages.append(new_message)
        db.session.add(new_message)
        db.session.commit()
        return request.json['message']
    elif request.method == 'GET':
        last_id = int(request.args.get('last_id'))
        passed_list = [x for x in current_conversation.messages if x.id > last_id]
        return jsonpickle.encode(passed_list)


@app.route('/create_conference', methods=['GET'])
def create_conference():
    users = User.query.all()
    new_convo = Conversation(is_conference=True)
    db.session.add(new_convo)
    db.session.commit()
    new_convo.users.append(current_user)
    new_convo.messages.append(Message(message='New conference created', timestamp='4:20', sender='Server'))
    new_invite = Invite(initiator=current_user.username, conference_id=new_convo.id)
    db.session.add(new_invite)
    db.session.commit()
    return render_template('create_conference.html', invite=new_invite, users=users)


@app.route('/api/send_invite/<username_to_query>', methods=['POST'])
def send_invite(username_to_query):
    invitee = User.query.filter_by(username=username_to_query).first()
    invite = Invite(initiator=request.json["initiator"], conference_id=request.json["conference_id"])
    invitee.invites.append(invite)
    db.session.add(invite)
    db.session.commit()
    return '<h1>Invite sent</h1>'


@app.route('/api/accept_invite/<cur_conf_id>', methods=['POST'])
def accept_invite(cur_conf_id):
    cur_conf = Conversation.query.filter_by(id=cur_conf_id).first()
    cur_conf.users.append(current_user)
    cur_conf.messages.append(Message(message='User ' + current_user.username + ' joined!', timestamp='4:20',
                                     sender='Server'))
    
    invite_id = request.json["invite_id"]
    invite = Invite.query.filter_by(id=invite_id).delete()

    db.session.commit()
    return '<h1>Invite accepted</h1>'

"""
@app.route('')
def user_page():
"""

@app.before_request
def before_request():
    g.user = current_user


@app.route('/logout')
def logout():
    user = current_user
    user.authenticated = False
    db.session.commit()
    logout_user()
    return render_template('logout.html')
