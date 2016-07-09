from flask import (render_template, url_for, redirect, request, session, g,
                   flash)

from .. import db
from ..email import send_email
from . import auth
from .decorators import login_required
from .forms import (LoginForm, RegistrationForm, PasswordResetRequestForm,
                    PasswordResetForm, ChangePasswordForm, ChangeEmailForm)
from .models import User


@auth.before_app_request
def load_user():
    username = session.get('username', False)
    if username:
        # TODO - process the case where there is no user, which means session
        # is not valid, needs to be updated
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
        # TODO - add logging of sent-mails
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash("A confirmation mail has been sent to you!")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", reg_form=reg_form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('username', False):
        flash("You are already logged in!")
        return redirect(url_for('main.index'))
    log_form = LoginForm()
    if log_form.validate_on_submit():
        user = User.query.filter_by(email=log_form.email.data).first()
        if user is not None and user.verify_password(log_form.password.data):
            if log_form.remember_me.data:
                session.permanent = True
            session['username'] = user.username
            flash("Login successful!")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid username or password")
            return render_template("auth/login.html", log_form=log_form), 401
    return render_template("auth/login.html", log_form=log_form)


@auth.route('/logout')
@login_required(redirect_to='main.index')
def logout():
    if session.get('username', False):
        session.pop('username')
        flash("Successfully logged out!")
        if session.permanent:
            session.permanent = False
    return redirect(url_for("main.index"))


# add login required here
@auth.route('/confirm/<token>')
def confirm(token):
    if g.get('user', False):
        if g.user.confirmed:
            flash("You have already confirmed your account.")
        elif g.user.confirm(token):
            flash("You have confirmed your account. Thanks!")
        else:
            flash("The confirmation link is invalid or has expired.")
        return redirect(url_for("main.index"))
    else:
        flash("You have to be logged in first!")
        return redirect(url_for('auth.login'))


@auth.route('/confirm')
def resend_confirmation():
    user = g.get('user', None)
    if user:
        if not user.confirmed:
            token = user.generate_confirmation_token()
            send_email(user.email, 'Confirm Your Accout', 'auth/email/confirm',
                       user=user, token=token)
            flash("A new confirmation has been sent to you by email.")
        else:
            flash("You have already confirmed your account.")
    return redirect(url_for("main.index"))


@auth.route('/unconfirmed')
def unconfirmed():
    if g.get('user', False):
        if not g.user.confirmed:
            return render_template("auth/unconfirmed.html", user=g.user)
        else:
            flash("You have already confirmed your account!")
    return redirect(url_for("main.index"))


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if g.get('user', False):
        flash("You are currently logged in!")
        return redirect(url_for('main.index'))
    req_form = PasswordResetRequestForm()
    if req_form.validate_on_submit():
        user = User.query.filter_by(email=req_form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password', user=user, token=token)
        flash("An email with instructions to reset your password is sent")
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=req_form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not g.get('user', False):
        reset_form = PasswordResetForm()
        if reset_form.validate_on_submit():
            user = User.query.filter_by(email=reset_form.email.data).first()
            if user is None:
                return redirect(url_for('main.index'))
            if user.reset_password(token, reset_form.password.data):
                flash("Your password has been updated!")
                return redirect(url_for('auth.login'))
            else:
                flash("Failed to reset password")
                return redirect(url_for('main.index'))
        return render_template('auth/reset_password.html', form=reset_form)
    else:
        flash("You are currently logged in!")
        return redirect(url_for('main.index'))


@auth.route('/change_password', methods=['GET', 'POST'])
@login_required(redirect_to='auth.login')
def change_password():
    user = g.get('user', False)
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.add(user)
        flash("Your password has been updated")
        return redirect(url_for("main.index"))
    else:
        flash("Invalid password.")
    return render_template("auth/change_password.html", form=form)


@auth.route('/change_email', methods=['GET', 'POST'])
@login_required(redirect_to='auth.login')
def change_email_request():
    user = g.user
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if user.verify_password(form.password.data):
            new_email = form.email.data
            token = user.generate_change_mail_token(new_email)
            send_email(new_email, "Confirm your email address",
                       "auth/email/change_email", user=user, token=token)
            flash("An email with instructions to confirm was sent")
            return redirect(url_for('main.index'))
        else:
            flash("Invalid email or password.")
    return render_template("auth/change_email.html", form=form)


@auth.route('/change_email/<token>')
@login_required(redirect_to='auth.login')
def change_email(token):
    user = g.user
    if user.change_email(token):
        flash("Your email address has been updated.")
    else:
        flash("Invalid request.")
    return redirect(url_for('main.index'))
