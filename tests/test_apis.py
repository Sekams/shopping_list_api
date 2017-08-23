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
        self.new_user = {'username': 'homie', 'password': 'duff',
                         'first_name': 'Homer', 'last_name': 'Simpson'}
        self.user = {'username': 'homie', 'password': 'duff'}
        self.user_pw_rst = {'username': 'homie', 'new_password': 'beer'}

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Teardown all initialized variables."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    unittest.main()
