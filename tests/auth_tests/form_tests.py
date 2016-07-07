import unittest

from compass import create_app, db
from compass.auth.forms import RegistrationForm
from compass.auth.models import User


class RegistrationFormTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('testing')

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()

    def tearDown(self):
        db.drop_all()
        self.context.pop()

    def test_registration_form_validates(self):
        form = RegistrationForm()
        form.username.data = 'username'
        form.email.data = 'mail@mail.com'
        form.password.data = 'password'
        form.password2.data = 'password'
        self.assertTrue(form.validate())

    def test_registration_form_does_not_validate_if_username_taken(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        form = RegistrationForm()
        form.username.data = 'user'
        form.email.data = 'mail2@mail.com'
        form.password.data = 'password'
        form.password2.data = 'password'
        self.assertFalse(form.validate())

    def test_registration_form_does_not_validate_if_email_taken(self):
        u = User(username='user', password='password', email='mail@mail.com')
        db.session.add(u)
        db.session.commit()
        form = RegistrationForm()
        form.username.data = 'user2'
        form.email.data = 'mail@mail.com'
        form.password.data = 'password'
        form.password2.data = 'password'
        self.assertFalse(form.validate())


if __name__ == "__main__":
    unittest.main()
