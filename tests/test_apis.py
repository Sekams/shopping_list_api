import unittest
import json
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
        self.new_user = {'username': 'homie', 'email': 'homie@duffbeer.com', 'password': 'duffbeer'}
        self.user = {'username': 'homie', 'password': 'duffbeer'}
        self.user_pw_rst = {'old_password': 'duffbeer', 'new_password': 'beerduff'}

        with self.app.app_context():
            db.create_all()

    def test_index(self):
        """Test API renders index page"""
        res = self.client().get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn('Shopping List API Documentation', str(res.data))

    def test_invalid_email_1(self):
        """Test API detect invalid email (POST request)"""
        self.new_user['email'] = 'homie.duffbeer.com'
        res = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Email address is invalid', str(res.data))

    def test_invalid_email_2(self):
        """Test API detect an invalid email (POST request)"""
        self.new_user['email'] = 'homie@duffbeercom'
        res = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Email address is invalid', str(res.data))

    def test_invalid_password(self):
        """Test API detect an invalid password (POST request)"""
        self.new_user['password'] = 'duff'
        res = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Password should be at least 6 characters', str(res.data))

    def test_no_data(self):
        """Test API detect no data (POST request)"""
        self.new_user['email'] = 'homie@duffbeercom'
        res = self.client().post('/v1/auth/register', data={})
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter values for username, password, email', str(res.data))

    def test_incomplete_data(self):
        """Test API detect incomplete data (POST request)"""
        self.new_user['email'] = 'homie@duffbeercom'
        res = self.client().post('/v1/auth/register', data=self.user)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter value for email', str(res.data))


    def test_incomplete_data_2(self):
        """Test API detect incomplete user data (POST request)"""
        self.new_user['email'] = 'homie@duffbeercom'
        res = self.client().post('/v1/auth/register', data=self.user)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter value for email', str(res.data))

    def test_missing_data(self):
        """Test API detect missing user data (POST request)"""
        self.new_user['email'] = 'homie@duffbeercom'
        res = self.client().post('/v1/auth/register', data={'password': 'duffbeer'})
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter values for username, email', str(res.data))

    def test_empty_data(self):
        """Test API detect empty user data (POST request)"""
        self.new_user['email'] = 'homie@duffbeercom'
        res = self.client().post('/v1/auth/register', data={'username': '', 'email': '', 'password': 'duffbeer'})
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter values for username, email', str(res.data))

    def test_register(self):
        """Test API can create a new user (POST request)"""
        res = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(res.status_code, 201)
        self.assertIn('You registered successfully. Please log in.', str(res.data))

    def test_register_exception(self):
        """Test API can catch registration exception (POST request)"""
        res = self.client().post('/v1/auth/register', data={"username": str("abc" * 100), "password": "123456", "email": "this.is@not.working"})
        self.assertEqual(res.status_code, 500)
        self.assertIn('Something went wrong. Please try again', str(res.data))

    def test_login(self):
        """Test API can login a user (POST request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        res = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(res.status_code, 200)
        self.assertIn('You logged in successfully.', str(res.data))

    def test_login_invalid_data(self):
        """Test API can catch login invalid data (POST request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        res = self.client().post('/v1/auth/login', data={"username": "", "password": "123456"})
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter value for username', str(res.data))

    def test_logout(self):
        """Test API can logout a user (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        res = self.client().post('/v1/auth/logout', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        self.assertIn('Successfully logged out.', str(res.data))

    def test_logout_invalid(self):
        """Test API can catch invalid logout data (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        res = self.client().post('/v1/auth/logout', headers=dict(Authorization="Bearer "))
        self.assertEqual(res.status_code, 403)
        self.assertIn('Provide an authentication token.', str(res.data))


    def test_invalid_token(self):
        """Test API can detect invalid token (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        res = self.client().post('/v1/auth/logout', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        res_2 = self.client().post('/v1/auth/logout', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res_2.status_code, 401)
        self.assertIn('Provide a valid authentication token.', str(res_2.data))

    def test_reset_password(self):
        """Test API can reset a user password (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/auth/reset-password',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.user_pw_rst)
        self.assertEqual(res.status_code, 201)
        self.assertIn('You have successfully changed your password.', str(res.data))

    def test_reset_password_incomplete(self):
        """Test API can catch incomplete info for password reset (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.user_pw_rst["old_password"] = ""     
        res = self.client().post('/v1/auth/reset-password',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.user_pw_rst)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Please provide the required parameter value for old_password', str(res.data))

    def test_reset_password_wrong_old_password(self):
        """Test API can catch wrong old password for password reset (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.user_pw_rst["old_password"] = "3ffefref3f"     
        res = self.client().post('/v1/auth/reset-password',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.user_pw_rst)
        self.assertEqual(res.status_code, 401)
        self.assertIn('Invalid old password', str(res.data))

    def test_reset_no_token(self):
        """Test API can catch a missing token (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/auth/reset-password',
                                 headers=dict(Authorization="Bearer "),
                                 data=self.user_pw_rst)
        self.assertEqual(res.status_code, 403)
        self.assertIn('Provide an authentication token.', str(res.data))

    def test_reset_invalid_token(self):
        """Test API can catch an invalid token for resetting password (POST request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/auth/reset-password',
                                 headers=dict(Authorization="Bearer " + "env3irbv3riei"),
                                 data=self.user_pw_rst)
        self.assertEqual(res.status_code, 401)
        self.assertIn('Provide a valid authentication token.', str(res.data))

    def test_shopping_list_creation(self):
        """Test API can create a shopping list (POST request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/shoppinglists/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.shopping_list_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('From Supermarket', str(res.data))

    def test_shopping_list_creation_no_token(self):
        """Test API can catch a missing token in shopping list (POST request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/shoppinglists/',
                                 headers=dict(Authorization="Bearer "),
                                 data=self.shopping_list_1)
        self.assertEqual(res.status_code, 403)
        self.assertIn('Provide an authentication token.', str(res.data))

    def test_shopping_list_duplication(self):
        """Test API can duplicate a shopping list (POST request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/shoppinglists/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.shopping_list_1)
        res_2 = self.client().post('/v1/shoppinglists/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.shopping_list_1)
        self.assertEqual(res_2.status_code, 409)
        self.assertIn('Shopping List already exists', str(res_2.data))

    def test_shopping_list_retrieval(self):
        """Test API can get a shopping list (GET request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post('/v1/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_2)
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().get('/v1/shoppinglists/', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        self.assertIn('From Farmers market', str(res.data))

    def test_shopping_list_retrieval_by_id(self):
        """Test API can get a single shopping list by using it's id. (GET request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post('/v1/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        result_in_json = json.loads(rv_3.data.decode('utf-8').replace("'", "\""))
        import pdb
        result = self.client().get(
            '/v1/shoppinglists/{}'.format(result_in_json['shoppingList']['id']),
            headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(result.status_code, 200)
        self.assertIn('From Supermarket', str(result.data))

    def test_shopping_list_editing(self):
        """Test API can edit an existing shopping list. (PUT request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post(
            '/v1/shoppinglists/',
            headers=dict(Authorization="Bearer " + access_token),
            data={'title': 'Christmas List'})
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().put(
            '/v1/shoppinglists/1',
            headers=dict(Authorization="Bearer " + access_token),
            data={
                "new_title": "Easter List"
            })
        self.assertEqual(rv_4.status_code, 200)
        results = self.client().get('/v1/shoppinglists/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertIn('Easter List', str(results.data))

    def test_shopping_list_deletion(self):
        """Test API can delete an existing shopping list. (DELETE request)."""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']
        rv_3 = self.client().post(
            '/v1/shoppinglists/',
            headers=dict(Authorization="Bearer " + access_token),
            data={'title': 'List 1'})
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().delete('/v1/shoppinglists/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        result = self.client().get('/v1/shoppinglists/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(result.status_code, 404)

    def test_shopping_list_item_creation(self):
        """Test API can create a shopping list item (POST request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/v1/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        res = self.client().post('/v1/shoppinglists/1/items/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.item_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('Sugar', str(res.data))

    def test_shopping_list_item_editing(self):
        """Test API can edit an existing shopping list item (PUT request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/v1/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_2)
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().post('/v1/shoppinglists/1/items/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.item_2)
        self.assertEqual(rv_4.status_code, 201)
        res = self.client().put(
            '/v1/shoppinglists/1/items/1',
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
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        access_token = json.loads(rv_2.data.decode())['access_token']
        self.assertEqual(rv_2.status_code, 200)
        rv_3 = self.client().post('/v1/shoppinglists/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.shopping_list_1)
        self.assertEqual(rv_3.status_code, 201)
        rv_4 = self.client().post('/v1/shoppinglists/1/items/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.item_1)
        self.assertEqual(rv_4.status_code, 201)
        res = self.client().delete('/v1/shoppinglists/1/items/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(res.status_code, 200)
        self.assertIn('Shopping list Item \\\'Sugar\\\' deleted', str(res.data))

    def test_shopping_list_search(self):
        """Test API can search for a shopping list (GET request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/shoppinglists/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.shopping_list_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('From Supermarket', str(res.data))
        search_res =  self.client().get('/v1/shoppinglists/search/shoppinglist/From/1/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(search_res.status_code, 200)
        self.assertIn('From Supermarket', str(search_res.data))

    def test_shopping_list_item_search(self):
        """Test API can search for a shopping list item (GET request)"""
        rv = self.client().post('/v1/auth/register', data=self.new_user)
        self.assertEqual(rv.status_code, 201)
        rv_2 = self.client().post('/v1/auth/login', data=self.user)
        self.assertEqual(rv_2.status_code, 200)
        access_token = json.loads(rv_2.data.decode())['access_token']     
        res = self.client().post('/v1/shoppinglists/',
                                 headers=dict(Authorization="Bearer " + access_token),
                                 data=self.shopping_list_1)
        self.assertEqual(res.status_code, 201)
        self.assertIn('From Supermarket', str(res.data))
        rv_4 = self.client().post('/v1/shoppinglists/1/items/',
                                  headers=dict(Authorization="Bearer " + access_token),
                                  data=self.item_1)
        self.assertEqual(rv_4.status_code, 201)
        search_res =  self.client().get('/v1/shoppinglists/search/item/Sugar/1/1', headers=dict(Authorization="Bearer " + access_token))
        self.assertEqual(search_res.status_code, 200)
        self.assertIn('Sugar', str(search_res.data))

    def tearDown(self):
        """Teardown all initialized variables."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    unittest.main()
