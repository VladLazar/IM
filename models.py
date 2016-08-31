from app import db
from flask_login import UserMixin
from flask import json

relationship_table = db.Table('relationship_table',
                              db.Column('conversation_id', db.Integer, db.ForeignKey('user.id')),
                              db.Column('user_id', db.Integer, db.ForeignKey('conversation.id'))
)


class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column('username', db.String(100), unique=True, index=True)
    password = db.Column('password', db.String(100))
    email = db.Column('email', db.String(100), unique=True, index=True)
    authenticated = db.Column('authenticated', db.Boolean, default=False)

    def __init__(self, username, password, email, authenticated):
        self.username = username
        self.password = password
        self.email = email
        self.authenticated = authenticated

    def __repr__(self):
        return '<User %r>' % self.username

    def get_id(self):
        return self.id

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class Conversation(db.Model):
    __tablename__ = 'conversation'

    id = db.Column('id', db.Integer, primary_key=True)
    users = db.relationship("User", secondary=relationship_table)
    messages = db.relationship("Message", backref="conversation", lazy="dynamic")


class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column('id', db.Integer, primary_key=True)
    message = db.Column('message', db.String)
    timestamp = db.Column('timestamp', db.String)
    sender = db.Column('sender', db.String)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))

    def __init__(self, message, timestamp, sender):
        self.message = message
        self.timestamp = timestamp
        self.sender = sender

    def __repr__(self):
        return '<%r: %r>' % (self.sender, self.message)


