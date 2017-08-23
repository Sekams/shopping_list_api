import unittest
from flask import current_app
from flask_testing import TestCase
from server import create_app

app = create_app('testing')

class TestDevelopmentConfig(TestCase):
    """Test the Development configuration"""
    def create_app(self):
        """Create instance of the app with development configurations"""
        app.config.from_object('server.config.DevelopmentConfig')
        return app

    def test_app_is_development(self):
        """Test app has Development configuration"""
        self.assertFalse(app.config['SECRET_KEY'] is 'this-is-my-secret-key-dont-tell-anyone-else')
        self.assertTrue(app.config['DEBUG'] is True)
        self.assertFalse(current_app is None)
        self.assertTrue(
            app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://postgres:1234@localhost/shopping_list_api'
        )


class TestTestingConfig(TestCase):
    """Test the Testing configuration"""
    def create_app(self):
        """Create instance of the app with testing configurations"""
        app.config.from_object('server.config.TestingConfig')
        return app

    def test_app_is_testing(self):
        """Test app has Testing configuration"""
        self.assertFalse(app.config['SECRET_KEY'] is 'this-is-my-secret-key-dont-tell-anyone-else')
        self.assertTrue(app.config['DEBUG'])
        self.assertTrue(
            app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://postgres:1234@localhost/shopping_list_api_test'
        )


class TestProductionConfig(TestCase):
    """Test the Production configuration"""
    def create_app(self):
        """Create instance of the app with production configurations"""
        app.config.from_object('server.config.ProductionConfig')
        return app

    def test_app_is_production(self):
        """Test app has Production configuration"""
        self.assertTrue(app.config['DEBUG'] is False)


if __name__ == '__main__':
    unittest.main()
