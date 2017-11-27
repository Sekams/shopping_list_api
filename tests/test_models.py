import unittest
from server import create_app, db
from server.models import User, BlacklistToken, ShoppingList, Item


class UserTestCase(unittest.TestCase):

    def setUp(self):
        """Set up test variables."""
        self.app = create_app("testing")

        self.user = User(
            'regina_phalange', 'regina@example.com', '123456')

        with self.app.app_context():
            # create all tables
            db.session.close()
            db.drop_all()
            db.create_all()

    def test_auth_token_exception(self):
        """Test authentication token exception"""
        self.assertEqual("Object of type '_BoundDeclarativeMeta' is not JSON serializable",
                         self.user.generate_auth_token(User, 1))


    def test_invalid_auth_token(self):
        """Test invalid authentication token"""
        with self.app.app_context():
            self.user.save()
            self.assertEqual("Invalid token. Please log in again.", self.user.decode_auth_token("riignrgnrg"))

    def test_expired_auth_token(self):
        """Test expired authentication token"""

        with self.app.app_context():
            self.user.save()
            user = User.query.filter_by(username=self.user.username).first()
            token = self.user.generate_auth_token(user.id, -86400)
            self.assertEqual("Signature expired. Please log in again.", self.user.decode_auth_token(token))
