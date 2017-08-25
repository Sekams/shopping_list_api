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
        self.item_1 = {'name': 'Sugar', 'price': '2000', 'status': 'True'}
        self.item_2 = {'name': 'Salt', 'price': '2000', 'status': 'True'}
        self.shopping_list_1 = {'title': 'From Supermarket'}
        self.shopping_list_2 = {'title': 'From Farmers market'}
        self.shopping_lists = [self.shopping_list_1, self.shopping_list_2]
        self.new_user = {'username': 'homie', 'email': 'homie@duff.com', 'password': 'duff'}
        self.user = {'username': 'homie', 'password': 'duff'}
        self.user_pw_rst = {'old_password': 'duff', 'new_password': 'beer'}

        with self.app.app_context():
            db.create_all()

    def test_register(self):
        """Test API can create a new user (POST request)"""
        res = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(res.status_code, 201)
        self.assertIn('You registered successfully. Please log in.', str(res.data))

    def test_login(self):
        """Test API can login a user (POST request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        res = self.client().post('/auth/login', data=self.user)
        self.assertEqual(res.status_code, 200)
        self.assertIn('You logged in successfully.', str(res.data))

    def test_logout(self):
        """Test API can logout a user (POST request)."""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        res = self.client().post('/auth/logout', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        self.assertIn('Successfully logged out.', str(res.data))

    def test_reset_password(self):
        """Test API can reset a user password (POST request)."""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/auth/reset-password',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.user_pw_rst)
        self.assertEqual(res.status_code, 201)
        self.assertIn('You have successfully changed your password.', str(res.data))

    def test_shopping_list_creation(self):
        """Test API can create a shopping list (POST request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/shoppinglists/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.shopping_list_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('From Supermarket', str(res.data))

    def test_shopping_list_retrieval(self):
        """Test API can get a shopping list (GET request)."""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post('/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_2)
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().get('/shoppinglists/', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        self.assertIn('From Farmers market', str(res.data))

    def test_shopping_list_retrieval_by_id(self):
        """Test API can get a single shopping list by using it's id. (GET request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post('/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        result_in_json = json.loads(rv_3.data.decode('utf-8').replace("'", "\""))
        result = self.client().get(
            '/shoppinglists/{}'.format(result_in_json['id']),
            headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(result.status_code, 200)
        self.assertIn('From Supermarket', str(result.data))

    def test_shopping_list_editing(self):
        """Test API can edit an existing shopping list. (PUT request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post(
            '/shoppinglists/',
            headers=dict(Authorization="Bearer " + access_token),
            data={'title': 'Christmas List'})
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().put(
            '/shoppinglists/1',
            headers=dict(Authorization="Bearer " + access_token),
            data={
                "new_title": "Easter List"
            })
        self.assertEqual(rv_4.status_code, 200)
        results = self.client().get('/shoppinglists/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertIn('Easter List', str(results.data))

    def test_shopping_list_deletion(self):
        """Test API can delete an existing shopping list. (DELETE request)."""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post(
            '/shoppinglists/',
            headers=dict(Authorization="Bearer " + access_token),
            data={'title': 'List 1'})
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().delete('/shoppinglists/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        result = self.client().get('/shoppinglists/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(result.status_code, 404)

    def test_shopping_list_item_creation(self):
        """Test API can create a shopping list item (POST request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().post('/shoppinglists/1/items/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.item_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('Sugar', str(res.data))

    def test_shopping_list_item_editing(self):
        """Test API can edit an existing shopping list item (PUT request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_2)
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().post('/shoppinglists/1/items/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.item_2)
        self.assertEqual(rv_4.status_code, 201)
        res = self.client().put(
            '/shoppinglists/1/items/1',
            headers=dict(Authorization="Bearer " + access_token),
            data={
                "new_name": "Butter",
                "new_price": "2000",
                "new_status": "False"
            })
        self.assertEqual(res.status_code, 200)
        self.assertIn('Butter', str(res.data))

    def test_shopping_list_item_deletion(self):
        """Test API can delete an existing shopping list item (DELETE request)"""
        rv = self.client().post('/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/auth/login', data=self.user)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().post('/shoppinglists/1/items/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.item_1)
        self.assertEqual(rv_4.status_code, 201)
        res = self.client().delete('/shoppinglists/1/items/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        self.assertIn('Shopping list Item 1 deleted', str(res.data))

    def tearDown(self):
        """Teardown all initialized variables."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    unittest.main()
