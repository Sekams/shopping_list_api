"""This module defines the models of the application"""
from datetime import datetime, timedelta
from server.config import secret_key
from flask_bcrypt import Bcrypt
from server import db
import jwt

class User(db.Model):
    """Model for the user table"""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    modified_on = db.Column(db.DateTime, nullable=False)
    shopping_lists = db.relationship(
        'ShoppingList', order_by='ShoppingList.id', cascade="all, delete-orphan")

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = Bcrypt().generate_password_hash(password).decode()
        self.created_on = datetime.now()
        self.modified_on = datetime.now()

    def validate_password(self, password):
        """
        Checking the password
        """
        return Bcrypt().check_password_hash(self.password, password)

    def generate_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(hours=24),
                'iat': datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                secret_key,
                algorithm='HS256'
            )
        except Exception as e:
            return str(e)

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, secret_key, algorithms=['HS256'])
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    def save(self):
        db.session.add(self)
        db.session.commit()


class ShoppingList(db.Model):
    """Model for the shopping_list table"""
    __tablename__ = 'shoppingLists'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), unique=True, nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    modified_on = db.Column(db.DateTime, nullable=False)
    items = db.relationship('Item', order_by='Item.id',
                            cascade="all, delete-orphan")
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))

    def __init__(self, title, user_id):
        self.title = title
        self.user_id = user_id
        self.created_on = datetime.now()
        self.modified_on = datetime.now()

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all(user_db_id):
        return ShoppingList.query.filter_by(user_id=user_db_id)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<ShoppingList {}}>'.format(self.title)


class Item(db.Model):
    """Model for the item table"""
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    price = db.Column(db.Integer)
    status = db.Column(db.Boolean)
    created_on = db.Column(db.DateTime, nullable=False)
    modified_on = db.Column(db.DateTime, nullable=False)
    shopping_list_id = db.Column(db.Integer, db.ForeignKey(ShoppingList.id))

    def __init__(self, name, price, status, shopping_list_id):
        self.name = name
        self.price = price
        self.status = status
        self.created_on = datetime.now()
        self.modified_on = datetime.now()
        self.shopping_list_id = shopping_list_id

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all():
        return Item.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<Item {}>'.format(self.name)


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklistTokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False
