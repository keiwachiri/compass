import unittest
import time

from compass import create_app, db
from compass.auth.models import User


class UserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('testing')

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        # Should be moved to setUpClass method to increase speed
        db.create_all()
        self.user = User(username='user', password='pass',
                         email='example@mail.com')

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_by_default_User_is_not_confirmed(self):
        self.assertFalse(self.user.confirmed)

    # Password-related tests
    def test_passwords_are_stored_as_hash(self):
        self.assertIsNotNone(self.user.password_hash)

    def test_password_is_not_accessible_attribute(self):
        with self.assertRaises(AttributeError):
            self.user.password

    def test_password_setter_changes_hash(self):
        hash1 = self.user.password_hash
        self.user.password = "new_password"
        hash2 = self.user.password_hash
        self.assertNotEqual(hash1, hash2)

    def test_verify_password_checks_hash(self):
        self.assertFalse(self.user.verify_password('wrong_pass'))
        self.assertTrue(self.user.verify_password('pass'))

    def test_passwords_are_salted(self):
        u2 = User(username='user2', password='pass', email='example2@mail.com')
        self.assertNotEqual(u2.password_hash, self.user.password_hash)

    # Confirmation-token testing
    def test_generate_confirmation_token_returns_byte_string(self):
        token = self.user.generate_confirmation_token()
        self.assertEqual(type(token), bytes)

    def test_confirm_returns_true_on_correct_token_and_confirms_user(self):
        token = self.user.generate_confirmation_token()
        self.assertFalse(self.user.confirmed)
        self.assertTrue(self.user.confirm(token))
        self.assertTrue(self.user.confirmed)

    def test_confirm_returns_false_on_wrong_token_and_doesnt_confirm(self):
        token = self.user.generate_confirmation_token()
        u2 = User(username='user2', password='pass', email='example2@mail.com')
        db.session.add(u2)
        db.session.commit()
        self.assertFalse(u2.confirm(token))
        self.assertFalse(u2.confirmed)

    def test_confirm_returns_false_and_doesnt_confirm_on_expired_token(self):
        token = self.user.generate_confirmation_token(expiration=1)
        time.sleep(2)
        self.assertFalse(self.user.confirm(token))
        self.assertFalse(self.user.confirmed)

    # Reset-password testing
    def test_generate_reset_token_returns_byte_string_object(self):
        token = self.user.generate_reset_token()
        self.assertEqual(type(token), bytes)

    def test_reset_password_changes_password_with_right_token(self):
        token = self.user.generate_reset_token()
        self.assertTrue(self.user.reset_password(token, 'new_password'))
        self.assertTrue(self.user.verify_password('new_password'))

    def test_reset_password_doesnt_change_password_on_wrong_token(self):
        u2 = User(username='user2', password='pass', email='example2@mail.com')
        db.session.add(u2)
        db.session.commit()
        token = u2.generate_reset_token()
        self.assertFalse(self.user.reset_password(token, 'new_password'))
        self.assertFalse(self.user.verify_password('new_password'))

    def test_reset_password_doesnt_change_password_when_token_expired(self):
        token = self.user.generate_reset_token(expiration=1)
        time.sleep(2)
        self.assertFalse(self.user.reset_password(token, 'new_password'))
        self.assertFalse(self.user.verify_password('new_password'))


if __name__ == "__main__":
    unittest.main()
