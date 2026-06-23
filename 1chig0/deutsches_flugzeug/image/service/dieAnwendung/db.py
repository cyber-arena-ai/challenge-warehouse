import sqlite3
from flask import g, current_app


DATABASE = 'data/datenbank.sqlite3'


def init_app(app):
    app.teardown_appcontext(close_connection)
    init_db(app)


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def init_db(dieApplikation):
    datenbank = get_db()
    with current_app.open_resource('schema.sql') as f:
        datenbank.executescript(f.read().decode('utf8'))
    dieApplikation.logger.info("Database created")


def close_connection(exception):
    db = getattr(g, '_database', None)
    g.pop('_database', None)
    if db is not None:
        db.close()
