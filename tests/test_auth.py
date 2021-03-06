import unittest
import json
from server import create_app, db


class AuthTestCase(unittest.TestCase):
    """Test case for the authentication blueprint."""

    def setUp(self):
        """Set up test variables."""
        self.app = create_app("testing")
        # initialize the test client
        self.client = self.app.test_client
        # This is the user test json data with a predefined email and password
        self.new_user_data = {
            'username': 'test',
            'email': 'test@example.com',
            'password': 'test_password'
        }

        self.user_data = {
            'username': 'test',
            'password': 'test_password'
        }

        with self.app.app_context():
            # create all tables
            db.session.close()
            db.drop_all()
            db.create_all()

    def test_registration(self):
        """Test user registration works correcty."""
        res = self.client().post('/v1/auth/register', data=self.new_user_data)
        # get the results returned in json format
        result = json.loads(res.data.decode())
        # assert that the request contains a success message and a 201 status code
        self.assertEqual(result['message'],
                         "You registered successfully. Please log in.")
        self.assertEqual(res.status_code, 201)

    def test_registration_invalid_data(self):
        """Test user registration with invalid data."""
        res = self.client().post('/v1/auth/register', data=self.user_data)
        result = json.loads(res.data.decode())
        self.assertEqual(result['message'],
                         "Please provide the required parameter value for email")
        self.assertEqual(res.status_code, 400)

    def test_already_registered_user(self):
        """Test that a user cannot be registered twice."""
        res = self.client().post('/v1/auth/register', data=self.new_user_data)
        self.assertEqual(res.status_code, 201)
        second_res = self.client().post('/v1/auth/register', data=self.new_user_data)
        self.assertEqual(second_res.status_code, 409)
        # get the results returned in json format
        result = json.loads(second_res.data.decode())
        self.assertEqual(
            result['message'], "User already exists. Please login.")

    def test_user_login(self):
        """Test registered user can login."""
        res = self.client().post('/v1/auth/register', data=self.new_user_data)
        self.assertEqual(res.status_code, 201)
        login_res = self.client().post('/v1/auth/login', data=self.user_data)

        # get the results in json format
        result = json.loads(login_res.data.decode())
        # Test that the response contains success message
        self.assertEqual(result['message'], "You logged in successfully.")
        # Assert that the status code is equal to 200
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(result['access_token'])

    def test_non_registered_user_login(self):
        """Test non registered users cannot login."""
        # define a dictionary to represent an unregistered user
        not_a_user = {
            'username': 'not_a_user',
            'password': 'nopesir'
        }
        # send a POST request to /v1/auth/login with the data above
        res = self.client().post('/v1/auth/login', data=not_a_user)
        # get the result in json
        result = json.loads(res.data.decode())

        # assert that this response must contain an error message
        # and an error status code 401(Unauthorized)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(
            result['message'], "Invalid username or password, Please try again")

    def test_invalid_password_user_login(self):
        """Test invalid password user can login."""
        res = self.client().post('/v1/auth/register', data=self.new_user_data)
        self.assertEqual(res.status_code, 201)
        self.user_data['password'] = '123456'
        login_res = self.client().post('/v1/auth/login', data=self.user_data)
        result = json.loads(login_res.data.decode())
        self.assertEqual(result['message'], "Invalid username or password, Please try again")
        self.assertEqual(login_res.status_code, 401)
