from flask_api import FlaskAPI
from flask import request, jsonify, abort
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from server.config import app_config

db = SQLAlchemy()

def create_app(config_name):
    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    db.init_app(app)

    @app.route("/")
    def main():
        return 'Welcome to the Shopping List API!'

    from .auth import auth_blueprint, shoppinglists_blueprint
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(shoppinglists_blueprint)

    return app

def create_heroku_app():
    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config['production'])
    db.init_app(app)
    db.create_all()
    db.session.commit()
