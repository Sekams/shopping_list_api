postgres_local_database = "postgresql://postgres:@localhost/"
database_name = "shopping_list_api"
secret_key = "this-is-my-secret-key-dont-tell-anyone-else"

class BaseConfig:
    """Base application configuration"""
    SECRET_KEY = secret_key
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = postgres_local_database + database_name


class TestingConfig(BaseConfig):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_local_database + database_name + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False


class ProductionConfig(BaseConfig):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgres://vaczwgnjmdzpxy:1f129d08b4f8c2d74c4eacded7ebf0f079500bfda27852750c66455f3c3eddde@ec2-54-247-123-130.eu-west-1.compute.amazonaws.com:5432/d8anijloibs5sj'

app_config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}
