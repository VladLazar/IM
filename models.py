from app import db


class User(db.Model):
    __tablename__ = 'user'

    username = db.Column('username', db.String(100), unique=True, index=True, primary_key=True)
    password = db.Column('password', db.String(100))
    email = db.Column('email', db.String(100), unique=True, index=True)
    authenticated = db.Column('authenticated', db.Boolean, default=False)

    def __init__(self, username, password, email, authenticated):
        self.username = username
        self.password = password
        self.email = email
        self.authenticated = authenticated

    def is_active(self):
        """All users are active"""
        return True

    def get_id(self):
        return self.username

    def is_authenticated(self):
        """Return True if user is authenticated"""
        return self.authenticated

    def is_anonymous(self):
        """False, anonymous users not supported"""
        return False

    def __repr__(self):
        return '<User %r>' % self.username
