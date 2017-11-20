from . import auth_blueprint, shoppinglists_blueprint
from datetime import datetime
from flask.views import MethodView
from flask import make_response, request, jsonify
from server.models import db, User, ShoppingList, Item, BlacklistToken, Bcrypt
from server.helpers import validate_required, validate_token


class RegisterAPI(MethodView):
    """This class registers a new user."""

    def post(self):
        """Handle POST request for this view. Url ---> /v1/auth/register"""

        if validate_required(request.data, 'username', 'password', 'email')['status'] == 'success':
            # Query to see if the user already exists
            user = User.query.filter_by(
                username=request.data['username'].lower()).first()

            if not user:
                # There is no user so we'll try to register them
                try:
                    post_data = request.data
                    # Register the user
                    username = post_data['username'].lower()
                    email = post_data['email']
                    password = post_data['password']
                    user = User(username=username,
                                email=email, password=password)
                    user.save()

                    response = {
                        'status': 'success',
                        'message': 'You registered successfully. Please log in.'
                    }
                    # return a response notifying the user that they registered successfully
                    return make_response(jsonify(response)), 201
                except Exception as e:
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                # There is an existing user. We don't want to register users twice
                # Return a message to the user telling them that they they already exist
                response = {
                    'status': 'fail',
                    'message': 'User already exists. Please login.'
                }

                return make_response(jsonify(response)), 409
        else:
            return validate_required(request.data, 'username', 'password', 'email'), 400


class LoginAPI(MethodView):
    """This class handles user login and access token generation."""

    def post(self):
        """Handle POST request for this view. Url ---> /v1/auth/login"""

        if validate_required(request.data, 'username', 'password')['status'] == 'success':
            try:
                # Get the user object using their email (unique to every user)
                user = User.query.filter_by(
                    username=request.data['username'].lower()).first()

                # Try to authenticate the found user using their password
                if user and user.validate_password(request.data['password']):
                    # Generate the access token. This will be used as the authorization header
                    access_token = user.generate_auth_token(user.id)
                    if access_token:
                        response = {
                            'status': 'success',
                            'message': 'You logged in successfully.',
                            'access_token': access_token.decode()
                        }
                        return make_response(jsonify(response)), 200
                else:
                    # User does not exist. Therefore, we return an error message
                    response = {
                        'status': 'fail',
                        'message': 'Invalid username or password, Please try again'
                    }
                    return make_response(jsonify(response)), 401

            except Exception as e:
                # Create a response containing an string error message
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                # Return a server error using the HTTP Error Code 500 (Internal Server Error)
                return make_response(jsonify(response)), 500
        else:
            return validate_required(request.data, 'username', 'password'), 400


class LogoutAPI(MethodView):
    """This class handles user logout"""

    def post(self):
        auth_token = validate_token(request)
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
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'Provide a valid authentication token.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ResetPasswordAPI(MethodView):
    """This class resets a user password."""

    def post(self):
        """Handle POST request for this view. Url ---> /v1/auth/reset-password"""

        auth_token = validate_token(request)
        if auth_token:
            if validate_required(request.data, 'old_password', 'new_password')['status'] == 'success':
                try:
                    user_id = User.decode_auth_token(auth_token)
                    if not isinstance(user_id, str):
                        user = User.query.filter_by(id=user_id).first()
                        if user and user.validate_password(request.data['old_password']):
                            user.password = Bcrypt().generate_password_hash(
                                request.data['new_password']).decode()
                            user.modified_on = datetime.now()
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
                            'message': 'Provide a valid authentication token.'
                        }
                        return make_response(jsonify(responseObject)), 401
                except Exception as e:
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                return validate_required(request.data, 'old_password', 'new_password'), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListAPI(MethodView):
    """This class handles multiple shopping lists"""

    def post(self):
        """Handle POST request for this view. Url ---> /v1/shoppinglists/"""

        auth_token = validate_token(request)
        if auth_token:
            if validate_required(request.data, 'title')['status'] == 'success':
                try:
                    user_id = User.decode_auth_token(auth_token)
                    if not isinstance(user_id, str):
                        user = User.query.filter_by(id=user_id).first()
                        if user:
                            shoppinglist = ShoppingList.query.filter_by(
                                title=request.data['title'], user_id=user_id).first()
                            if shoppinglist:
                                response = {
                                    'status': 'fail',
                                    'message': 'Shopping List already exists'
                                }
                                return make_response(jsonify(response)), 409
                            title = str(request.data['title'])
                            if title:
                                shopping_list = ShoppingList(
                                    title=title, user_id=user_id)
                                shopping_list.save()

                                response = {
                                    'status': 'success',
                                    'message': 'Shopping list created',
                                    'shoppingList': {
                                        'id': shopping_list.id,
                                        'title': shopping_list.title,
                                        'user_id': user_id,
                                        'created_on': shopping_list.created_on,
                                        'modified_on': shopping_list.modified_on
                                    }
                                }
                                return make_response(jsonify(response)), 201

                        else:
                            response = {
                                'status': 'fail',
                                'message': 'User not found'
                            }
                            return make_response(jsonify(response)), 404
                    else:
                        responseObject = {
                            'status': 'fail',
                            'message': 'Provide a valid authentication token.'
                        }
                        return make_response(jsonify(responseObject)), 401
                except Exception as e:
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                return validate_required(request.data, 'title'), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403

    def get(self):
        """Handle GET request for this view. Url ---> /v1/shoppinglists/"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    user = User.query.filter_by(id=user_id).first()
                    if user:
                        shopping_lists = ShoppingList.query.filter_by(
                            user_id=user_id)

                        if not shopping_lists:
                            response = {
                                'status': 'fail',
                                'message': 'No shopping lists found'
                            }
                            return make_response(jsonify(response)), 404
                        results = []
                        for shopping_list in shopping_lists:
                            results.append(
                                {
                                    'id': shopping_list.id,
                                    'title': shopping_list.title,
                                    'user_id': shopping_list.user_id,
                                    'created_on': shopping_list.created_on,
                                    'modified_on': shopping_list.modified_on
                                }
                            )
                        response = {
                            'status': 'success',
                            'message': 'Shopping lists found',
                            'shoppingLists': results
                        }
                        return make_response(jsonify(response)), 200
                    else:
                        response = {
                            'status': 'fail',
                            'message': 'User not found'
                        }
                        return make_response(jsonify(response)), 404
                else:
                    responseObject = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(responseObject)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListIdAPI(MethodView):
    """This class handles a single shopping list"""

    def get(self, id):
        """Handle GET request for this view. Url ---> /v1/shoppinglists/<id>"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                # Get the user id related to this access token
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    # If the id is not a string(error), we have a user id
                    # Get the bucketlist with the id specified from the URL (<int:id>)
                    shoppinglist = ShoppingList.query.filter_by(id=id).first()
                    if not shoppinglist:
                        # There is no bucketlist with this ID for this User, so
                        # Raise an HTTPException with a 404 not found status code
                        responseObject = {
                            'status': 'fail',
                            'message': 'Shopping List not found.'
                        }
                        return make_response(jsonify(responseObject)), 404
                    response = {
                        'status': 'success',
                        'message': 'Shopping List found.',
                        'shoppingList': {
                            'id': shoppinglist.id,
                            'title': shoppinglist.title,
                            'user_id': shoppinglist.user_id,
                            'created_on': shoppinglist.created_on,
                            'modified_on': shoppinglist.modified_on
                        }
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 500
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403

    def put(self, id):
        """Handle PUT request for this view. Url ---> /v1/shoppinglists/<id>"""

        auth_token = validate_token(request)
        if auth_token:
            if validate_required(request.data, 'new_title')['status'] == 'success':
                try:
                    # Get the user id related to this access token
                    user_id = User.decode_auth_token(auth_token)
                    if not isinstance(user_id, str):
                        # If the id is not a string(error), we have a user id
                        # Get the bucketlist with the id specified from the URL (<int:id>)
                        shoppinglist = ShoppingList.query.filter_by(
                            id=id).first()
                        if not shoppinglist:
                            # There is no bucketlist with this ID for this User, so
                            # Raise an HTTPException with a 404 not found status code
                            responseObject = {
                                'status': 'fail',
                                'message': 'Shopping List not found.'
                            }
                            return make_response(jsonify(responseObject)), 404
                        new_title = str(request.data['new_title'])

                        shoppinglist.title = new_title
                        shoppinglist.modified_on = datetime.now()
                        shoppinglist.save()
                        response = {
                            'status': 'success',
                            'message': 'Shopping List edited.',
                            'shoppingList': {
                                'id': shoppinglist.id,
                                'title': shoppinglist.title,
                                'user_id': shoppinglist.user_id,
                                'created_on': shoppinglist.created_on,
                                'modified_on': shoppinglist.modified_on
                            }
                        }
                        return make_response(jsonify(response)), 200
                    else:
                        response = {
                            'status': 'fail',
                            'message': 'Provide a valid authentication token.'
                        }
                        return make_response(jsonify(response)), 401
                except Exception as e:
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                return validate_required(request.data, 'new_title'), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403

    def delete(self, id):
        """Handle DELETE request for this view. Url ---> /v1/shoppinglists/<id>"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                # Get the user id related to this access token
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                        # If the id is not a string(error), we have a user id
                        # Get the bucketlist with the id specified from the URL (<int:id>)
                    shoppinglist = ShoppingList.query.filter_by(id=id).first()
                    if not shoppinglist:
                        # There is no bucketlist with this ID for this User, so
                        # Raise an HTTPException with a 404 not found status code
                        responseObject = {
                            'status': 'fail',
                            'message': 'Shopping List not found.'
                        }
                        return make_response(jsonify(responseObject)), 404
                    shoppinglist.delete()
                    response = {
                        "status": "success",
                        "message": "Shopping list '{}' deleted".format(shoppinglist.title)
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 500
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListIdItemsAPI(MethodView):
    """This class handles multiple shopping list items."""

    def post(self, id):
        """Handle POST request for this view. Url ---> /v1/shoppinglists/<id>/items/"""

        auth_token = validate_token(request)
        if auth_token:
            if validate_required(request.data, 'name', 'price', 'status')['status'] == 'success':
                try:
                    user_id = User.decode_auth_token(auth_token)
                    if not isinstance(user_id, str):
                        user = User.query.filter_by(id=user_id).first()
                        if user:
                            shoppinglist = ShoppingList.query.filter_by(
                                id=id).first()
                            if not shoppinglist:
                                response = {
                                    'status': 'fail',
                                    'message': 'Shopping List not found'
                                }
                                return make_response(jsonify(response)), 404

                            name = str(request.data['name'])
                            price = str(request.data['price'])
                            status = str(request.data['status'])
                            if name:
                                shoppinglistitem = Item.query.filter_by(
                                    name=name, shopping_list_id=id).first()
                                if shoppinglistitem:
                                    response = {
                                        'status': 'fail',
                                        'message': 'Shopping List Item exists'
                                    }
                                    return make_response(jsonify(response)), 409
                                if price:
                                    price = int(price)
                                status_bool = False
                                if status:
                                    if status.lower == 'true':
                                        status_bool = True

                                item = Item(
                                    name=name, price=price, status=status_bool, shopping_list_id=id, user_id=user_id)
                                item.save()
                                response = {
                                    'status': 'success',
                                    'message': 'Shopping List Item created.',
                                    'shoppingListItem': {
                                        'id': item.id,
                                        'name': item.name,
                                        'price': item.price,
                                        'status': item.status,
                                        'created_on': item.created_on,
                                        'modified_on': item.modified_on,
                                        'shopping_list_id': item.shopping_list_id
                                    }
                                }
                                return make_response(jsonify(response)), 201

                            else:
                                response = {
                                    'status': 'fail',
                                    'message': 'Please enter Item name'
                                }
                                return make_response(jsonify(response)), 401
                        else:
                            response = {
                                'status': 'fail',
                                'message': 'User not found'
                            }
                            return make_response(jsonify(response)), 404
                    else:
                        response = {
                            'status': 'fail',
                            'message': 'Provide a valid authentication token.'
                        }
                        return make_response(jsonify(response)), 401
                except Exception as e:
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                return validate_required(request.data, 'name', 'price', 'status'), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403

    def get(self, id):
        """Handle GET request for this view. Url ---> /v1/shoppinglists/<id>/items/"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    user = User.query.filter_by(id=user_id).first()
                    if user:
                        shoppinglist = ShoppingList.query.filter_by(
                            id=id).first()
                        if not shoppinglist:
                            response = {
                                'status': 'fail',
                                'message': 'Shopping List not found'
                            }
                            return make_response(jsonify(response)), 404

                        shoppinglistitems = Item.query.filter_by(
                            shopping_list_id=id).all()
                        if shoppinglistitems:
                            items = []
                            for item in shoppinglistitems:
                                items.append(
                                    {
                                        'id': item.id,
                                        'name': item.name,
                                        'price': item.price,
                                        'status': item.status,
                                        'created_on': item.created_on,
                                        'modified_on': item.modified_on,
                                        'shopping_list_id': item.shopping_list_id
                                    }
                                )
                            response = {
                                'status': 'success',
                                'message': 'Shopping List Items found.',
                                'shoppingListItems': items
                            }
                            return make_response(jsonify(response)), 200
                        else:
                            response = {
                                'status': 'fail',
                                'message': 'No Shopping List Items found'
                            }
                            return make_response(jsonify(response)), 404
                    else:
                        response = {
                            'status': 'fail',
                            'message': 'User not found'
                        }
                        return make_response(jsonify(response)), 404
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 500
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListIdItemsIdAPI(MethodView):
    """This class handles a single shopping list item"""

    def get(self, id, item_id):
        """Handle GET request for this view. Url ---> /v1/shoppinglists/<id>/items/<item_id>"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    shoppinglist = ShoppingList.query.filter_by(id=id).first()
                    if not shoppinglist:
                        response = {
                            'status': 'fail',
                            'message': 'Shopping List not found'
                        }
                        return make_response(jsonify(response))
                    item = Item.query.filter_by(id=item_id).first()
                    if not item:
                        response = {
                            'status': 'fail',
                            'message': 'Shopping List Item not found'
                        }
                        return make_response(jsonify(response)), 404
                    response = {
                        'status': 'success',
                        'message': 'Shopping List Item found.',
                        'shoppingListItem': {
                            'id': item.id,
                            'name': item.name,
                            'price': item.price,
                            'status': item.status,
                            'created_on': item.created_on,
                            'modified_on': item.modified_on,
                            'shopping_list_id': item.shopping_list_id
                        }
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 500
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403

    def put(self, id, item_id):
        """Handle PUT request for this view. Url ---> /v1/shoppinglists/<id>/items/<item_id>"""

        auth_token = validate_token(request)
        if auth_token:
            if validate_required(request.data, 'new_name', 'new_price', 'new_status')['status'] == 'success':
                try:
                    # Get the user id related to this access token
                    user_id = User.decode_auth_token(auth_token)
                    if not isinstance(user_id, str):
                        shoppinglist = ShoppingList.query.filter_by(
                            id=id).first()
                        item = Item.query.filter_by(id=item_id).first()
                        if not shoppinglist or not item:
                            response = {
                                'status': 'fail',
                                'message': 'Shopping List not found'
                            }
                            return make_response(jsonify(response)), 404
                        new_name = str(request.data['new_name'])
                        new_price = str(request.data['new_price'])
                        new_status = str(request.data['new_status'])

                        item.name = new_name
                        item.price = new_price
                        item.status = new_status
                        item.modified_on = datetime.now()
                        item.save()
                        response = {
                            'status': 'success',
                            'message': 'Shopping List Item edited.',
                            'shoppingListItem': {
                                'id': item.id,
                                'name': item.name,
                                'price': item.price,
                                'status': item.status,
                                'created_on': item.created_on,
                                'modified_on': item.modified_on,
                                'shopping_list_id': item.shopping_list_id
                            }
                        }
                        return make_response(jsonify(response)), 200
                    else:
                        response = {
                            'status': 'fail',
                            'message': 'Provide a valid authentication token.'
                        }
                        return make_response(jsonify(response)), 401
                except Exception as e:
                    # An error occured, therefore return a string message containing the error
                    response = {
                        'status': 'fail',
                        'message': 'Something went wrong. Please try again: ' + str(e)
                    }
                    return make_response(jsonify(response)), 500
            else:
                return validate_required(request.data, 'new_name', 'new_price', 'new_status'), 400

        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403

    def delete(self, id, item_id):
        """Handle DELETE request for this view. Url ---> /v1/shoppinglists/<id>/items/<item_id>"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    shoppinglist = ShoppingList.query.filter_by(id=id).first()
                    if not shoppinglist:
                        response = {
                            'status': 'fail',
                            'message': 'Shopping List not found'
                        }
                        return make_response(jsonify(response)), 404
                    item = Item.query.filter_by(id=item_id).first()
                    if not item:
                        response = {
                            'status': 'fail',
                            'message': 'Shopping List Item not found'
                        }
                        return make_response(jsonify(response)), 404
                    item.delete()
                    response = {
                        "status": "success",
                        "message": "Shopping list Item '{}' deleted".format(item.name)
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ShoppingListSearchAPI(MethodView):
    """This class handles the shopping list search functionality"""

    def get(self, q, limit):
        """Handle GET request for this view. Url ---> /v1/shoppinglists/search/shoppinglist/<q>/<limit>"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                # Get the user id related to this access token
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    # q = str(request.data['query'])
                    shoppinglists = ShoppingList.query.filter_by(
                        user_id=user_id)
                    if q:
                        shoppinglists = shoppinglists.filter(
                            ShoppingList.title.ilike(q.lower() + '%')
                        )

                    shoppinglists = shoppinglists.order_by(
                        ShoppingList.title).paginate(1, limit, error_out=False).items

                    if not shoppinglists:
                        response = {
                            'status': 'fail',
                            'message': 'Shopping Lists not found'
                        }
                        return make_response(jsonify(response)), 404
                    the_lists = []
                    for a_list in shoppinglists:
                        the_lists.append(
                            {
                                'id': a_list.id,
                                'title': a_list.title,
                                'user_id': a_list.user_id,
                                'created_on': a_list.created_on,
                                'modified_on': a_list.modified_on
                            }
                        )
                    response = {
                        'status': 'success',
                        'message': 'Shopping Lists found.',
                        'shoppingLists': the_lists
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 500
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


class ItemSearchAPI(MethodView):
    """This class handles the shopping list item search functionality"""

    def get(self, q, limit):
        """Handle GET request for this view. Url ---> /v1/shoppinglists/search/item/<q>/<limit>"""

        auth_token = validate_token(request)
        if auth_token:
            try:
                # Get the user id related to this access token
                user_id = User.decode_auth_token(auth_token)
                if not isinstance(user_id, str):
                    items = None
                    if q:
                        items = Item.query.filter_by(user_id=user_id)
                        items = items.filter(Item.name.ilike(q + '%'))
                        items = items.order_by(Item.name).paginate(1, limit, error_out=False).items

                    if not items:
                        response = {
                            'status': 'fail',
                            'message': 'Shopping List Items not found'
                        }
                        return make_response(jsonify(response)), 404
                    the_items = []
                    for an_item in items:
                        the_items.append(
                            {
                                'id': an_item.id,
                                'name': an_item.name,
                                'price': an_item.price,
                                'status': an_item.status,
                                'created_on': an_item.created_on,
                                'modified_on': an_item.modified_on,
                                'shopping_list_id': an_item.shopping_list_id
                            }
                        )
                    response = {
                        'status': 'success',
                        'message': 'Shopping List Items found.',
                        'shoppingListItems': the_items
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'status': 'fail',
                        'message': 'Provide a valid authentication token.'
                    }
                    return make_response(jsonify(response)), 401
            except Exception as e:
                # An error occured, therefore return a string message containing the error
                response = {
                    'status': 'fail',
                    'message': 'Something went wrong. Please try again: ' + str(e)
                }
                return make_response(jsonify(response)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide an authentication token.'
            }
            return make_response(jsonify(responseObject)), 403


register_api = RegisterAPI.as_view('register_api')
login_api = LoginAPI.as_view('login_api')
logout_api = LogoutAPI.as_view('logout_api')
reset_password_api = ResetPasswordAPI.as_view('reset_password_api')
shopping_lists_api = ShoppingListAPI.as_view('shopping_lists_api')
shopping_lists_id_api = ShoppingListIdAPI.as_view('shopping_lists_id_api')
shopping_lists_id_items_api = ShoppingListIdItemsAPI.as_view(
    'shopping_lists_id_items_api')
shopping_lists_id_items_id_api = ShoppingListIdItemsIdAPI.as_view(
    'shopping_lists_id_items_id_api')
shopping_lists_search_api = ShoppingListSearchAPI.as_view(
    'shopping_lists_search_api')
items_search_api = ItemSearchAPI.as_view('items_search_api')


auth_blueprint.add_url_rule(
    '/v1/auth/register',
    view_func=register_api,
    methods=['POST'])

auth_blueprint.add_url_rule(
    '/v1/auth/login',
    view_func=login_api,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/v1/auth/logout',
    view_func=logout_api,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/v1/auth/reset-password',
    view_func=reset_password_api,
    methods=['POST']
)
shoppinglists_blueprint.add_url_rule(
    '/v1/shoppinglists/',
    view_func=shopping_lists_api,
    methods=['POST', 'GET']
)
shoppinglists_blueprint.add_url_rule(
    '/v1/shoppinglists/<int:id>',
    view_func=shopping_lists_id_api,
    methods=['DELETE', 'GET', 'PUT']
)
shoppinglists_blueprint.add_url_rule(
    '/v1/shoppinglists/<int:id>/items/',
    view_func=shopping_lists_id_items_api,
    methods=['POST', 'GET']
)
shoppinglists_blueprint.add_url_rule(
    '/v1/shoppinglists/<int:id>/items/<int:item_id>',
    view_func=shopping_lists_id_items_id_api,
    methods=['PUT', 'DELETE', 'GET']
)
shoppinglists_blueprint.add_url_rule(
    '/v1/shoppinglists/search/shoppinglist/<string:q>/<int:limit>',
    view_func=shopping_lists_search_api,
    methods=['GET']
)
shoppinglists_blueprint.add_url_rule(
    '/v1/shoppinglists/search/item/<string:q>/<int:limit>',
    view_func=items_search_api,
    methods=['GET']
)
