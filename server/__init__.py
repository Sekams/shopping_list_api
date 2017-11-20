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
    def not_allowed(error):
        response = {
            'status': 'fail',
            'message': 'Please check the url you entered and try again'
        }
        return make_response(jsonify(response), 405)

    @app.errorhandler(404)
    def not_found(error):
        response = {
            'status': 'fail',
            'message': 'Page not found'
        }
        return make_response(jsonify(response), 404)

    @app.errorhandler(500)
    def server_error(error):
        response = {
            'status': 'fail',
            'message': 'Something went wrong. Please try again'
        }
        return make_response(jsonify(response), 404)

    # decorator used to allow cross origin requests
    @app.after_request
    def apply_cross_origin_header(response):
        response.headers['Access-Control-Allow-Origin'] = '*'

        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET,HEAD,OPTIONS," \
                                                        "POST,PUT,DELETE"
        response.headers["Access-Control-Allow-Headers"] = "Access-Control-Allow-"\
            "Headers, Origin,Accept, X-Requested-With, Content-Type, " \
            "Access-Control-Request-Method, Access-Control-Request-Headers," \
            "Access-Control-Allow-Origin, Authorization"

        return response

    from .auth import auth_blueprint, shoppinglists_blueprint
    from .apiary.views import apiary
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(shoppinglists_blueprint)
    app.register_blueprint(apiary)

    return app
