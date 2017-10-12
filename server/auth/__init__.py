from flask import Blueprint

auth_blueprint = Blueprint('auth', __name__)
shoppinglists_blueprint = Blueprint('shoppinglists', __name__)

try:
    from . import views
except ImportError as e:
    from server.auth import views
