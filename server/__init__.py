from flask_api import FlaskAPI
from flask import jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from server.config import app_config

db = SQLAlchemy()

def create_app(config_name):
    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    db.init_app(app)

    @app.errorhandler(405)
    def not_found(error):
        response = {
            'status': 'fail',
            'message': 'Please check the url you entered and try again'
        }
        return make_response(jsonify(response), 405)

    from .auth import auth_blueprint, shoppinglists_blueprint
    from .apiary.views import apiary
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(shoppinglists_blueprint)
    app.register_blueprint(apiary)

    return app
