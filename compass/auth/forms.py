from flask.ext.wtf import Form
from wtforms import (BooleanField, StringField, SubmitField, PasswordField,
                     ValidationError)
from wtforms.validators import Required, Email, Regexp, EqualTo, Length

from .models import User


class RegistrationForm(Form):
    email = StringField("Email", validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField("Username", validators=[Required(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Username must contain ...')])
    password = PasswordField("Password", validators=[Required(),
        EqualTo("password2", message="Passwords must match.")])
    password2 = PasswordField("Confirm password", validators=[Required()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email already registered")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username already in use")


class LoginForm(Form):
    email = StringField("Email", validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField("Password", validators=[Required()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log in")


class PasswordResetRequestForm(Form):
    email = StringField("Email", validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField("Reset Password")


class PasswordResetForm(Form):
    email = StringField("Email", validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField("New Password", validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField("Confirm Password", validators=[Required()])
    submit = SubmitField("Reset Password")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError("Unknown email address")


class ChangePasswordForm(Form):
    old_password = PasswordField("Old Password", validators=[Required()])
    password = PasswordField("New Password", validators=[Required(),
                        EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField("Confirm Password", validators=[Required()])
    submit = SubmitField("Change Password")


class ChangeEmailForm(Form):
    email = StringField("New Email", validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField("Password", validators=[Required()])
    submit = SubmitField("Update Email Address")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email already registered.")
