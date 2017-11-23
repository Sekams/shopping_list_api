import unittest
from server import create_app, db
from server.models import User, BlacklistToken, ShoppingList, Item


class UserTestCase(unittest.TestCase):

    def setUp(self):
        """Set up test variables."""
        self.app = create_app("testing")

        self.invalid_user = User('regina', 'regina@example.com', '123456')

        with self.app.app_context():
            # create all tables
            db.session.close()
            db.drop_all()
            db.create_all()

    def test_invalid_auth_token(self):
        """Test invalid authentication token"""
        self.assertEqual("Object of type '_BoundDeclarativeMeta' is not JSON serializable", self.invalid_user.generate_auth_token(User))
