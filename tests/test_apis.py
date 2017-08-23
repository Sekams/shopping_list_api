import unittest
import json
import os
from server import create_app, db

class ShoppingListAPITestCase(unittest.TestCase):
    """This class represents the ShoppingListAPI test case"""

    def setUp(self):
        """Define test variables and initialize app."""
        self.app = create_app('testing')
        self.client = self.app.test_client
        self.item_1 = {'name': 'Sugar'}
        self.item_2 = {'name': 'Salt'}
        self.shopping_list_1 = {'title': 'From Supermarket'}
        self.shopping_list_2 = {'title': 'From Farmers market'}
        self.shopping_lists = [self.shopping_list_1, self.shopping_list_2]
        self.user = {'email': 'homie@duff.com', 'password': 'duff'}
        self.user_pw_rst = {'email': 'homie@duff.com', 'new_password': 'beer'}

        with self.app.app_context():
            db.create_all()

    def test_register(self):
        """Test API can create a new user (POST request)"""
        res = self.client().post('/auth/register', data=self.user)
        self.assertEqual(res.status_code, 201)
        self.assertIn('homie@duff.com', str(res.data))

    def test_login(self):
        """Test API can login a user (POST request)"""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        res = self.client().post('/auth/login', data=self.user)
        self.assertEqual(res.status_code, 200)
        self.assertIn('homie@duff.com', str(res.data))

    def test_logout(self):
        """Test API can logout a user (POST request)."""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        res = self.client().post('/auth/logout', data=self.user['email'])
        self.assertEqual(res.status_code, 200)
        self.assertIn('Logout Successful', str(res.data))

    def test_reset_password(self):
        """Test API can reset a user password (POST request)."""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        res = self.client().post('/auth/reset-password', data=self.user_pw_rst)
        self.assertEqual(res.status_code, 201)
        self.assertIn('homie@duff.com', str(res.data))

    def tearDown(self):
        """Teardown all initialized variables."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    unittest.main()
