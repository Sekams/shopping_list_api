"""This module defines the models of the application"""
import jwt
import datetime
from server import create_app, db, bcrypt
from instance import instance

app = create_app(instance)

class User(db.Model):
    """Model for the user table"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    shopping_lists = db.relationship(
        'ShoppingList', backref='users', lazy='dynamic')

    def __init__(self, email, password, shopping_lists):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.shopping_lists = shopping_lists

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
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

    @staticmethod
    def get_all():
        return User.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<User %r>' % self.email

class ShoppingList(db.Model):
    """Model for the shopping_list table"""
    __tablename__ = 'shoppingLists'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), unique=True, nullable=False)
    items = db.relationship('Item', backref='shoppingLists', lazy='dynamic')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __init__(self, title, items):
        self.title = title
        self.items = items

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all():
        return ShoppingList.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<ShoppingList %r>' % self.title

class Item(db.Model):
    """Model for the item table"""
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    price = db.Column(db.Integer)
    status = db.Column(db.Boolean)
    shopping_list_id = db.Column(db.Integer, db.ForeignKey('shoppingLists.id'))

    def __init__(self, name, price, status):
        self.name = name
        self.price = price
        self.status = status

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
        return '<Item %r>' % self.name
