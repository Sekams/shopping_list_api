from . import auth_blueprint, shoppinglists_blueprint

from flask.views import MethodView
from flask import make_response, request, jsonify, json, abort
from server.models import db, User, ShoppingList, BlacklistToken, Bcrypt


class RegisterAPI(MethodView):
    """This class registers a new user."""

    def post(self):
        """Handle POST request for this view. Url ---> /auth/register"""

        # Query to see if the user already exists
        user = User.query.filter_by(username=request.data['username']).first()

        if not user:
            # There is no user so we'll try to register them
            try:
                post_data = request.data
                # Register the user
                username = post_data['username']
                email = post_data['email']
                password = post_data['password']
                user = User(username=username, email=email, password=password)
                user.save()

                response = {
                    'message': 'You registered successfully. Please log in.'
                }
                # return a response notifying the user that they registered successfully
                return make_response(jsonify(response)), 201
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'message': str(e)
                }
                return make_response(jsonify(response)), 401
        else:
            # There is an existing user. We don't want to register users twice
            # Return a message to the user telling them that they they already exist
            response = {
                'message': 'User already exists. Please login.'
            }

            return make_response(jsonify(response)), 202


class LoginAPI(MethodView):
    """This class-based view handles user login and access token generation."""

    def post(self):
        """Handle POST request for this view. Url ---> /auth/login"""
        try:
            # Get the user object using their email (unique to every user)
            user = User.query.filter_by(
                username=request.data['username']).first()

            # Try to authenticate the found user using their password
            if user and user.validate_password(request.data['password']):
                # Generate the access token. This will be used as the authorization header
                access_token = user.generate_auth_token(user.id)
                if access_token:
                    response = {
                        'message': 'You logged in successfully.',
                        'access_token': access_token.decode()
                    }
                    return make_response(jsonify(response)), 200
            else:
                # User does not exist. Therefore, we return an error message
                response = {
                    'message': 'Invalid username or password, Please try again'
                }
                return make_response(jsonify(response)), 401

        except Exception as e:
            # Create a response containing an string error message
            response = {
                'message': str(e)
            }
            # Return a server error using the HTTP Error Code 500 (Internal Server Error)
            return make_response(jsonify(response)), 500


class LogoutAPI(MethodView):
    """
    Logout Resource
    """

    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class ResetPasswordAPI(MethodView):
    """This class registers a new user."""

    def post(self):
        """Handle POST request for this view. Url ---> /auth/reset-password"""

        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            user_id = User.decode_auth_token(auth_token)
            if not isinstance(user_id, str):
                user = User.query.filter_by(id=user_id).first()
                if user and user.validate_password(request.data['old_password']):
                    user.password = Bcrypt().generate_password_hash(
                        request.data['new_password']).decode()
                    user.save()

                    response = {
                        'status': 'success',
                        'message': 'You have successfully changed your password.'
                    }
                    return make_response(jsonify(response)), 201
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Invalid old password.'
                    }
                    return make_response(jsonify(response)), 401
            else:
                responseObject = {
                    'status': 'fail',
                    'message': user_id
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListAPI(MethodView):
    """This class registers a new user."""

    def post(self):
        """Handle POST request for this view. Url ---> /shoppinglists/"""

        auth_header = request.headers.get('Authorization')
        if auth_header:
            access_token = auth_header.split(" ")[1]
        else:
            access_token = ''
        if access_token:
            user_id = User.decode_auth_token(access_token)
            if not isinstance(user_id, str):
                user = User.query.filter_by(id=user_id).first()
                if user:
                    title = str(request.data['title'])
                    if title:
                        shopping_list = ShoppingList(
                            title=title, user_id=user_id)
                        shopping_list.save()
                        response = jsonify({
                            'id': shopping_list.id,
                            'title': shopping_list.title,
                            'user_id': user_id
                        })

                        return make_response(response), 201

                else:
                    response = {
                        'status': 'fail',
                        'message': 'Invalid old password.'
                    }
                    return make_response(jsonify(response)), 401
            else:
                responseObject = {
                    'status': 'fail',
                    'message': user_id
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403

    def get(self):
        """Handle GET request for this view. Url ---> /shoppinglists/"""

        auth_header = request.headers.get('Authorization')
        if auth_header:
            access_token = auth_header.split(" ")[1]
        else:
            access_token = ''
        if access_token:
            user_id = User.decode_auth_token(access_token)
            if not isinstance(user_id, str):
                user = User.query.filter_by(id=user_id).first()
                if user:
                    shopping_lists = ShoppingList.query.filter_by(
                        user_id=user_id)
                    results = []

                    for shopping_list in shopping_lists:
                        obj = {
                            'id': shopping_list.id,
                            'title': shopping_list.title,
                            'user_id': shopping_list.user_id
                        }
                        results.append(obj)

                    return make_response(jsonify(results)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Invalid old password.'
                    }
                    return make_response(jsonify(response)), 401
            else:
                responseObject = {
                    'status': 'fail',
                    'message': user_id
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListIdAPI(MethodView):
    def get(self, id):
        # get the access token from the authorization header
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(" ")[1]

        if access_token:
            # Get the user id related to this access token
            user_id = User.decode_auth_token(access_token)

            if not isinstance(user_id, str):
                # If the id is not a string(error), we have a user id
                # Get the bucketlist with the id specified from the URL (<int:id>)
                shoppinglist = ShoppingList.query.filter_by(id=id).first()
                if not shoppinglist:
                    # There is no bucketlist with this ID for this User, so
                    # Raise an HTTPException with a 404 not found status code
                    abort(404)
                response = {
                    'id': shoppinglist.id,
                    'title': shoppinglist.title,
                    'user_id': shoppinglist.user_id
                }
                return make_response(jsonify(response)), 200
            else:
                # user is not legit, so the payload is an error message
                message = user_id
                response = {
                    'message': message
                }
                # return an error response, telling the user he is Unauthorized
                return make_response(jsonify(response)), 401

    def put(self, id):
        # get the access token from the authorization header
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(" ")[1]

        if access_token:
            # Get the user id related to this access token
            user_id = User.decode_auth_token(access_token)

            if not isinstance(user_id, str):
                # If the id is not a string(error), we have a user id
                # Get the bucketlist with the id specified from the URL (<int:id>)
                shoppinglist = ShoppingList.query.filter_by(id=id).first()
                if not shoppinglist:
                    # There is no bucketlist with this ID for this User, so
                    # Raise an HTTPException with a 404 not found status code
                    abort(404)
                new_title = str(request.data['new_title'])

                shoppinglist.title = new_title
                shoppinglist.save()
                response = {
                    'id': shoppinglist.id,
                    'title': shoppinglist.title,
                    'user_id': shoppinglist.user_id
                }
                return make_response(jsonify(response)), 200
            else:
                # user is not legit, so the payload is an error message
                message = user_id
                response = {
                    'message': message
                }
                # return an error response, telling the user he is Unauthorized
                return make_response(jsonify(response)), 401

    def delete(self, id):
        # get the access token from the authorization header
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(" ")[1]

        if access_token:
                # Get the user id related to this access token
            user_id = User.decode_auth_token(access_token)

            if not isinstance(user_id, str):
                    # If the id is not a string(error), we have a user id
                    # Get the bucketlist with the id specified from the URL (<int:id>)
                shoppinglist = ShoppingList.query.filter_by(id=id).first()
                if not shoppinglist:
                    # There is no bucketlist with this ID for this User, so
                    # Raise an HTTPException with a 404 not found status code
                    abort(404)

                shoppinglist.delete()
                return {
                    "message": "Shopping list {} deleted".format(shoppinglist.id)
                }, 200
            else:
                # user is not legit, so the payload is an error message
                message = user_id
                response = {
                    'message': message
                }
                # return an error response, telling the user he is Unauthorized
                return make_response(jsonify(response)), 401


register_api = RegisterAPI.as_view('register_api')
login_api = LoginAPI.as_view('login_api')
logout_api = LogoutAPI.as_view('logout_api')
reset_password_api = ResetPasswordAPI.as_view('reset_password_api')
shopping_lists_api = ShoppingListAPI.as_view('shopping_lists_api')
shopping_lists_id_api = ShoppingListIdAPI.as_view('shopping_lists_id_api')

auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=register_api,
    methods=['POST'])

auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_api,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_api,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/reset-password',
    view_func=reset_password_api,
    methods=['POST']
)
shoppinglists_blueprint.add_url_rule(
    '/shoppinglists/',
    view_func=shopping_lists_api,
    methods=['POST', 'GET']
)
shoppinglists_blueprint.add_url_rule(
    '/shoppinglists/<int:id>',
    view_func=shopping_lists_id_api,
    methods=['DELETE', 'GET', 'PUT']
)
