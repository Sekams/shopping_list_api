"""This module runs the database migrations"""
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from server import db, create_app
from instance import instance
from server import models

app = create_app(instance)

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)

@manager.command
def create_db():
    """This method creates all the database tables"""
    db.create_all()

@manager.command
def drop_db():
    """This method drops all the tables in the database"""
    db.drop_all()

if __name__ == '__main__':
    manager.run()
