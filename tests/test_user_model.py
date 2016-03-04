import os
import unittest

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

from flasky import db, Role, User, Permission, AnonymousUser


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        #sqlalchemy connect database
        basedir = os.path.abspath(os.path.dirname(__file__))
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')
        self.app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
        self.app.config['FLASKY_ADMIN'] = '786497042@qq.com'
        db.create_all()
        Role.insert_roles()

    def tearDown(self):
        db.session.remove()
        # db.drop_all()

    def test_roles_and_permissions(self):
        Role.insert_roles()
        u = User(email='786497042@qq.com', password='cat')
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertTrue(u.can(Permission.MODERATE_COMMENTS))
        self.assertTrue(u.can(Permission.ADMINISTER))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))

