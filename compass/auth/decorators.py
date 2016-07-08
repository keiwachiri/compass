from functools import wraps

from flask import g, current_app, redirect, flash, url_for


def login_required(redirect_to='auth.login'):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not g.get('user', False):
                flash("You have to be logged in to perform this action.")
                return redirect(url_for(redirect_to))
            return func(*args, **kwargs)
        return decorated_view
    return decorator
