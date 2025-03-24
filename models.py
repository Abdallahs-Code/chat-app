from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)  
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp()) 
    
    sent_requests = db.relationship('FriendRequest', backref='sender', foreign_keys='FriendRequest.sender_id')
    received_requests = db.relationship('FriendRequest', backref='receiver', foreign_keys='FriendRequest.receiver_id')
    friends = db.relationship('Friends',
                              primaryjoin="or_(User.id==Friends.user1_id, User.id==Friends.user2_id)",
                              backref="user")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username}>'

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def __repr__(self):
        return f'<FriendRequest {self.sender_id} to {self.receiver_id}>'

class Friends(db.Model):
    __tablename__ = 'friends'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])
    
    def __repr__(self):
        return f'<Friends {self.user1_id} and {self.user2_id}>'

load_dotenv()
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if ENCRYPTION_KEY is None:
    raise ValueError("Encryption key not found! Set ENCRYPTION_KEY in your environment.")

ENCRYPTION_KEY = ENCRYPTION_KEY.encode()  
cipher = Fernet(ENCRYPTION_KEY)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False) 
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

    @staticmethod
    def encrypt_message(message):
        return cipher.encrypt(message.encode())

    @staticmethod
    def decrypt_message(encrypted_message):
        return cipher.decrypt(encrypted_message).decode()