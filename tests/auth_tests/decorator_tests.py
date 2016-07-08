import unittest

from flask import url_for, g
from flask.ext.testing import TestCase

from compass import create_app, db
from compass.auth.decorators import login_required


class DummyUser:
    def __init__(self, name):
        self.username = name
        self.confirmed = True


class LoginRequiredTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('testing')

    def create_app(self):
        return self.app

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def dummy_function(self):
        return "Test response"

    def test_login_required_wraps_function_properly(self):
        wrapped_func = login_required()(self.dummy_function)
        self.app.add_url_rule('/test_login_required', 'test_login_required',
                              wrapped_func)
        resp = self.client.get(url_for('test_login_required'))
        self.assertRedirects(resp, url_for('auth.login'))

    def test_login_required_doesnt_redirect_when_user_set_in_g(self):
        wrapped_func = login_required()(self.dummy_function)
        self.app.add_url_rule('/test_login_required_g_set',
                              'test_login_required_g_set', wrapped_func)
        with self.app.test_client() as c:
            g.user = DummyUser("dummy_user")
            resp = self.client.get(url_for('test_login_required_g_set'))
            self.assertEqual(resp.data, b'Test response')

    def test_dummy_function_returns_resp_when_login_required_not_set(self):
        self.app.add_url_rule('/test_login_required_not_set',
                              'test_login_required_not_set',
                              self.dummy_function)
        resp = self.client.get(url_for('test_login_required_not_set'))
        self.assertEqual(resp.data, b'Test response')

    def test_login_required_redirects_to_redirect_dest_argument(self):
        wrapped_func = login_required('main.index')(self.dummy_function)
        self.app.add_url_rule('/test_login_required_with_argument',
                              'test_login_required_with_argument',
                              wrapped_func)
        resp = self.client.get(url_for('test_login_required_with_argument'))
        self.assertRedirects(resp, url_for('main.index'))

    def test_login_required_with_dest_arg_doesnt_redirect_when_user_set(self):
        wrapped_func = login_required('main.index')(self.dummy_function)
        self.app.add_url_rule('/test_login_required_with_arg_with_user',
                              'test_login_required_with_arg_with_user',
                              wrapped_func)
        with self.app.test_client() as c:
            g.user = DummyUser("test-user")
            resp = c.get(url_for('test_login_required_with_arg_with_user'))
            self.assertEqual(resp.data, b'Test response')




if __name__ == "__main__":
    unittest.main()
