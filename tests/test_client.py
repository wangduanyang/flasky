import os
import unittest

from flask import Flask, url_for
from flask.ext.sqlalchemy import SQLAlchemy

from flasky import db, Role, User, Permission, AnonymousUser


class FlaskClientTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        #sqlalchemy connect database
        self.app.config['SECRET_KEY'] = 'hard to guess string'
        TESTING = True
        basedir = os.path.abspath(os.path.dirname(__file__))
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')
        self.app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
        self.app.config['FLASKY_ADMIN'] = '786497042@qq.com'
        WTF_CSRF_ENABLED = False
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client(use_cookies=True)

    def tearDown(self):
        db.session.remove()
        # db.drop_all()

    def test_home_page(self):
        response = self.client.get(url_for('index'))
        self.assertTrue('Stranger' in response.get_data(as_text=True))



