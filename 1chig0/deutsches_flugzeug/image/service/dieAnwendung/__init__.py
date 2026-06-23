from flask import Flask
import secrets


def init_app():
    dieApplikation = Flask(__name__, template_folder='dieSchablonen', static_folder='statisch')

    try:
        with open('data/secret.txt', 'r') as f:
            SECRET_KEY = f.read().strip()
    except FileNotFoundError:
        SECRET_KEY = secrets.token_urlsafe(42)
        with open('data/secret.txt', 'w') as f:
            f.write(SECRET_KEY)

    dieApplikation.config.from_mapping(
        SECRET_KEY=SECRET_KEY
    )
    # TODO config
    with dieApplikation.app_context():
        from . import db
        db.init_app(dieApplikation)
        from . import auth
        from .dieRouten import main
        dieApplikation.register_blueprint(main)
        dieApplikation.register_blueprint(auth.auth)
        return dieApplikation
