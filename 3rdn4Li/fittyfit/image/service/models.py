from datetime import datetime
from email.policy import default
from flask_sqlalchemy import SQLAlchemy

""" This file contains the database models.
"""

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    hash = db.Column(db.String, unique=True)
    seed = db.Column(db.String) 
    secret = db.Column(db.String)    
    admin = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        res = dict(user_id=self.user_id,
                    name=self.name,
                    seed=self.seed,
                    secret=self.secret,
                    timestamp=self.timestamp.strftime('%Y-%m-%d %H:%M:%S'))
        return res
    

class Report(db.Model):
    __tablename__ = 'report'

    report_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)    
