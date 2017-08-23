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

    def test_shopping_list_creation(self):
        """Test API can create a shopping list (POST request)"""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        res = self.client().post('/shoppinglists/', data=self.shopping_list_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('From Supermarket', str(res.data))

    def test_shopping_list_retrieval(self):
        """Test API can get a shopping list (GET request)."""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/shoppinglists/', data=self.shopping_list_2)
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().get('/shoppinglists/')
        self.assertEqual(res.status_code, 200)
        self.assertIn('From Farmers market', str(res.data))

    def test_shopping_list_retrieval_by_id(self):
        """Test API can get a single shopping list by using it's id. (GET request)"""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/shoppinglists/', data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        result_in_json = json.loads(rv_3.data.decode('utf-8').replace("'", "\""))
        result = self.client().get(
            '/shoppinglists/{}'.format(result_in_json['id']))
        self.assertEqual(result.status_code, 200)
        self.assertIn('From Supermarket', str(result.data))

    def test_shopping_list_editing(self):
        """Test API can edit an existing shopping list. (PUT request)"""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post(
            '/shoppinglists/',
            data={'title': 'Christmas List'})
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().put(
            '/shoppinglists/1',
            data={
                "title": "Easter List"
            })
        self.assertEqual(rv_4.status_code, 200)
        results = self.client().get('/shoppinglists/1')
        self.assertIn('Easter List', str(results.data))

    def test_shopping_list_deletion(self):
        """Test API can delete an existing shopping list. (DELETE request)."""
        rv = self.client().post('/auth/register', data=self.user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post(
            '/shoppinglists/',
            data={'name': 'List 1'})
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().delete('/shoppinglists/1')
        self.assertEqual(res.status_code, 200)
        result = self.client().get('/shoppinglists/1')
        self.assertEqual(result.status_code, 404)

    def tearDown(self):
        """Teardown all initialized variables."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    unittest.main()
