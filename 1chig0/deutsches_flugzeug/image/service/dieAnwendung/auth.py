import functools

from flask import Blueprint, render_template, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from .db import get_db

auth = Blueprint("auth", __name__, url_prefix='/auth')


@auth.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE benutzername = ?', (username,)
        ).fetchone()
        if username == "":
            return render_template("login.html")
        if user is None:
            return render_template("login.html", wrong_login=True)
        if not check_password_hash(user[2], password):
            return render_template("login.html", wrong_login=True)
        if error is None:
            session.clear()
            session['user_id'] = user[0]
            return redirect(url_for('main.dieStartseite'))
        return render_template("login.html", wrong_login=True)

    return render_template("login.html", wrong_login=False)


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username or not password:
            return render_template("signup.html")

        if error is None:
            try:
                db.execute(
                    "INSERT INTO users (benutzername, passwort, beschreibung, flug_auszeit) VALUES (?, ?, ?, 0)",
                    (username, generate_password_hash(password), "")
                )
                db.commit()
            except db.IntegrityError:
                return render_template("signup.html", wrong_signup=True)
            else:
                return redirect(url_for('auth.login'))
    return render_template("signup.html")


@auth.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.dieStartseite'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view


