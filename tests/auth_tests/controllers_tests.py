import unittest
import time

from flask import url_for, session, g
from flask.ext.testing import TestCase

from compass import create_app, db
from compass.auth.models import User


class ControllerTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('testing')

    # Required for TestCase
    def create_app(self):
        return self.app

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


class RegisterTest(ControllerTest):
    def test_register_renders_register_template_with_form_on_GET(self):
        response = self.client.get(url_for("auth.register"))
        self.assertTemplateUsed('auth/register.html')
        self.assertIn(b'type="submit" value="Register"', response.data)

    def test_register_creates_new_user_on_POST_request(self):
        response = self.client.post(url_for('auth.register'),
                data={'username': 'user', 'email': 'example@mail.com',
                      'password': 'pass', 'password2': 'pass'})
        u = User.query.filter_by(username='user').first()
        self.assertIsNotNone(u)
        self.assertRedirects(response, url_for('auth.login'))

    def test_register_renders_reg_template_with_form_on_bad_POST_request(self):
        response = self.client.post(url_for('auth.register'),
                data={'username': 'user', 'email': 'example@mail.com',
                      'password': 'pass', 'password2': 'pass2'})
        self.assertTemplateUsed('auth/register.html')


class LoginTest(ControllerTest):
    def test_login_renders_login_template_and_form_on_GET(self):
        response = self.client.get(url_for('auth.login'))
        self.assertTemplateUsed('auth/login.html')
        self.assert200(response)
        self.assertIn(b'type="submit" value="Log in"', response.data)

    def test_login_redirects_on_POSTand_sets_session(self):
        u = User(username='user', password='password',
                 email='example@mail.com')
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            resp = c.post(url_for('auth.login'),
                    data={'email': 'example@mail.com', 'password': 'password'})
            self.assertRedirects(resp, url_for('main.index'))
            self.assertTrue(session.get('username'))
            self.assertFalse(session.permanent)

    def test_login_with_remember_me_checked_sets_permanent_to_True(self):
        u = User(username='user', password='password',
                 email='example@mail.com')
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            resp = c.post(url_for("auth.login"),
                    data={'email': 'example@mail.com', 'password': 'password',
                          'remember_me': True})
            self.assertRedirects(resp, url_for('main.index'))
            self.assertTrue(session.get('username'))
            self.assertTrue(session.permanent)

    def test_login_renders_login_template_and_form_on_bad_POST(self):
        with self.app.test_client() as c:
            resp = c.post(url_for('auth.login'),
                    data={'email': 'example@mail.com', 'password': 'password'})
            self.assertTemplateUsed('auth/login.html')
            self.assertIn(b'Invalid username or password', resp.data)
            self.assert401(resp)
            self.assertFalse(session.get('username', False))

    def test_login_redirects_to_main_index_if_logged_in(self):
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess['username'] = 'test-user'
            resp = c.get(url_for('auth.login'))
            self.assertRedirects(resp, url_for('main.index'))


class LogoutTest(ControllerTest):
    def test_logout_cleans_the_session_when_logged_in(self):
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess['username'] = 'test-user'
            resp = c.get(url_for('auth.logout'))
            self.assertRedirects(resp, url_for('main.index'))
            self.assertIsNone(session.get('username', None))

    def test_logout_redirects_to_main_when_not_logged_in(self):
        with self.app.test_client() as c:
            resp = c.get(url_for('auth.logout'))
            self.assertRedirects(resp, url_for('main.index'))


class LoadUserHookTest(ControllerTest):
    def test_user_is_loaded_into_g_if_session_has_username(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess['username'] = 'user'
            resp = c.get(url_for("main.index"))
            self.assertEqual(g.user, u)

    def test_user_is_not_loaded_into_g_if_the_session_has_no_username(self):
        with self.app.test_client() as c:
            resp = c.get(url_for('main.index'))
            self.assertIsNone(g.get('user'), None)


class ConfirmTokenTest(ControllerTest):
    def test_confirm_confirms_user_when_token_is_right_and_user_in_sess(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess['username'] = 'user'
            resp = c.get(url_for("auth.confirm", token=token))
            self.assertTrue(u.confirmed)
            self.assertRedirects(resp, url_for('main.index'))

    def test_confirm_doesnt_confirm_user_when_token_is_wrong(self):
        u1 = User(username='user1', password='password', email='m1@mail.com')
        db.session.add(u1)
        u2 = User(username='user2', password='password', email='m2@mail.com')
        db.session.add(u2)
        db.session.commit()
        token = u2.generate_confirmation_token()
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess['username'] = 'user1'
            resp = c.get(url_for("auth.confirm", token=token))
            self.assertFalse(u1.confirmed)
            self.assertFalse(u2.confirmed)
            self.assertRedirects(resp, url_for('main.index'))

    def test_confirm_doesnt_confirm_user_when_token_expired(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(expiration=1)
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess['username'] = 'user'
            time.sleep(2)
            resp = c.get(url_for("auth.confirm", token=token))
            self.assertFalse(u.confirmed)
            self.assertRedirects(resp, url_for('main.index'))

    def test_confirm_redirects_to_log_in_if_no_user_in_g(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        resp = self.client.get(url_for('auth.confirm', token=token))
        self.assertRedirects(resp, url_for('auth.login'))


class UnconfirmedTest(ControllerTest):
    def test_unconfirmed_renders_unconfirmed_template(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            g.user = u
            resp = c.get(url_for('auth.unconfirmed'))
            self.assert200(resp)
            self.assertTemplateUsed('auth/unconfirmed.html')

    def test_unconfirmed_redirects_to_main_if_account_is_confirmed(self):
        u = User(username='user', password='password', email='mail@mail.com')
        u.confirmed = True
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            g.user = u
            resp = c.get(url_for('auth.unconfirmed'))
            self.assertRedirects(resp, url_for('main.index'))

    def test_unconfirmed_redirects_to_main_if_no_user_loaded(self):
        with self.app.test_client() as c:
            resp = c.get(url_for('auth.unconfirmed'))
            self.assertRedirects(resp, url_for('main.index'))


class PasswordResetRequestTest(ControllerTest):
    def test_password_reset_request_renders_template_on_GET(self):
        resp = self.client.get(url_for('auth.password_reset_request'))
        self.assertTemplateUsed('auth/reset_password.html')

    def test_password_reset_request_redirects_to_auth_login_on_POST(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        resp = self.client.post(url_for('auth.password_reset_request'),
                                data={'email': 'mail@mail.com'})
        self.assertRedirects(resp, url_for('auth.login'))

    def test_password_reset_request_redirects_to_auth_login_on_bad_POST(self):
        resp = self.client.post(url_for('auth.password_reset_request'),
                                data={'email': 'non_existant_mail@mail.com'})
        self.assertRedirects(resp, url_for('auth.login'))

    def test_password_reset_request_redirects_to__index_if_logged_on_GET(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            g.user = u
            resp = self.client.get(url_for('auth.password_reset_request'))
            self.assertRedirects(resp, url_for('main.index'))

    def test_password_reset_request_redirects_to_index_if_logged_on_POST(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        with self.app.test_client() as c:
            g.user = u
            resp = self.client.post(url_for('auth.password_reset_request'),
                                    data={'email': 'mail@mail.com'})
            self.assertRedirects(resp, url_for('main.index'))


class PasswordResetTest(ControllerTest):
    def test_password_reset_renders_template_on_GET(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        resp = self.client.get(url_for('auth.password_reset', token=token))
        self.assertTemplateUsed('auth/reset_password.html')

    def test_password_reset_resets_password_on_POST(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        resp = self.client.post(url_for('auth.password_reset', token=token),
            data={'email': 'mail@mail.com', 'password': 'new_password',
                  'password2': 'new_password'})
        self.assertRedirects(resp, url_for('auth.login'))
        self.assertTrue(u.verify_password('new_password'))

    def test_password_reset_fails_to_reset_on_POST_with_wrong_token(self):
        u1 = User(username='user1', password='password', email='m1@mail.com')
        u2 = User(username='user2', password='password', email='m2@mail.com')
        db.session.add_all([u1, u2])
        db.session.commit()
        token = u1.generate_reset_token()
        resp = self.client.post(url_for('auth.password_reset', token=token),
                data={'email': 'm2@mail.com', 'password': 'new_password',
                      'password2': 'new_password'})
        self.assertRedirects(resp, url_for('main.index'))
        self.assertTrue(u2.verify_password('password'))

    def test_password_reset_fails_to_reset_on_POST_with_expired_token(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token(expiration=1)
        time.sleep(2)
        resp = self.client.post(url_for('auth.password_reset', token=token),
                data={'email': 'mail@mail.com', 'password': 'new_password',
                      'password2': 'new_password'})
        self.assertRedirects(resp, url_for('main.index'))
        self.assertFalse(u.verify_password('new_password'))

    def test_password_reset_redirects_to_main_on_GET_if_user_logged(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        with self.app.test_client() as c:
            g.user = u
            resp = c.get(url_for('auth.password_reset', token=token))
            self.assertRedirects(resp, url_for('main.index'))

    def test_password_reset_redirects_to_main_on_POST_if_user_logged(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        with self.app.test_client() as c:
            g.user = u
            resp = c.post(url_for('auth.password_reset', token=token),
                    data={'email': 'mail@mail.com', 'password': 'new_password',
                          'password2': 'new_password'})
            self.assertRedirects(resp, url_for('main.index'))




if __name__ == "__main__":
    unittest.main()
