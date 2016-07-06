from flask import (render_template, url_for, redirect, request, session, g,
                   flash)

from .. import db
from ..email import send_email
from . import auth
from .forms import LoginForm, RegistrationForm
from .models import User


@auth.before_app_request
def load_user():
    username = session.get('username', False)
    if username:
        g.user = User.query.filter_by(username=username).first()


@auth.before_app_request
def redirect_unconfirmed():
    if g.get('user', False):
        if (not g.user.confirmed and request.endpoint[:5] != 'auth.' and
            request.endpoint != 'static'):
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    reg_form = RegistrationForm()
    if reg_form.validate_on_submit():
        user = User(username=reg_form.username.data,
                    email=reg_form.email.data,
                    password=reg_form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash("A confirmation mail has been sent to you!")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", reg_form=reg_form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    log_form = LoginForm()
    if log_form.validate_on_submit():
        user = User.query.filter_by(email=log_form.email.data).first()
        if user is not None and user.verify_password(log_form.password.data):
            if log_form.remember_me.data:
                session.permanent = True
            session['username'] = user.username
            flash("Login successful!")
            return redirect(url_for("main.index"))
        flash("Invalid username or password")
    return render_template("auth/login.html", log_form=log_form)


@auth.route('/logout')
def logout():
    if session.get('username', False):
        session.pop('username')
        flash("Successfully logged out!")
        if session.permanent:
            session.permanent = False
    else:
        flash("You are not logged in!")
    return redirect(url_for("main.index"))


# add login required here
@auth.route('/confirm/<token>')
def confirm(token):
    if g.get('user', False):
        if g.user.confirmed:
            return redirect(url_for("main.index"))
        elif g.user.confirm(token):
            flash("You have confirmed your account. Thanks!")
        else:
            flash("The confirmation link is invalid or has expired.")
    return redirect(url_for("main.index"))


@auth.route('/confirm')
def resend_confirmation():
    user = g.get('user', None)
    if user:
        if not user.confirmed:
            token = user.generate_confirmation_token()
            send_email(user.email, 'Confirm Your Accout', 'auth/email/confirm',
                       user=user, token=token)
            flash("A new confirmation has been senr to you by email.")
        else:
            flash("You have already confirmed your account.")
            return redirect(url_for("main.index"))
    else:
        return redirect(url_for("main.index"))


@auth.route('/unconfirmed')
def unconfirmed():
    if g.get('user', False):
        if g.user.confirmed:
            return redirect(url_for("main.index"))
    return render_template("auth/unconfirmed.html", user=g.user)
