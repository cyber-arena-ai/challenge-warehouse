from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import jwt
import os
from dotenv import load_dotenv
from flask_cors import CORS
import logging
from sqlalchemy import and_
import uuid

load_dotenv()

DB_USER = os.getenv('DB_USER') or 'root'
DB_PASS = os.getenv('DB_PASS') or 'example'
DB_NAME = os.getenv('DB_NAME') or 'chatapp'
DB_HOST = os.getenv('DB_HOST') or 'db'

SECRET = str(uuid.uuid4())

app = Flask(__name__)
CORS(app) # TODO

# handler = logging.StreamHandler()
# handler.setLevel(logging.INFO)
# app.logger.addHandler(handler)

guni_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = guni_logger.handlers
app.logger.setLevel(logging.DEBUG)

db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:3306/{DB_NAME}' # "sqlite:///project.db"
db.init_app(app)

users = db.Table('users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('chatroom_id', db.Integer, db.ForeignKey('chatroom.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100))

    messages = db.relationship("Message", back_populates="user")
    chatrooms = db.relationship('Chatroom', secondary=users, back_populates="users")


class Chatroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    messages = db.relationship("Message", back_populates="chatroom")
    users = db.relationship('User', secondary=users, back_populates="chatrooms")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'))

    chatroom = db.relationship("Chatroom", back_populates="messages")
    user = db.relationship("User", back_populates="messages")

with app.app_context():
    db.create_all()

@app.before_request 
def check_user():
    auth_header = request.headers.get('X-Auth-Token', '')
    app.logger.info(auth_header)
    if auth_header:
        try:
            data = jwt.decode(auth_header, SECRET, algorithms=["HS256"])
            app.logger.info(data)
            name = data.get("user", "")
            g.user = User.query.filter_by(username=name).first()
            app.logger.info(g.user)
        except:
            g.user = None
    else:
        g.user = None


@app.route('/')
def index():
    return 'Welcome to the chat API!'

@app.route('/register', methods=["POST"])
def register():
    if g.user:
        data = {"error": "User already logged in."}
        return jsonify(data), 400

    name = request.json.get('name', '')
    password = request.json.get('password', '')

    users = User.query.all()

    if next((True for user in users if user.username == name), False):
        data = {"error": "User already exists"}
        return jsonify(data), 400

    try:
        new_user = User(username=name, password=generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        app.logger.error(e)
        data = {"error": "Something went wrong."}
        return jsonify(data), 400
    
    session = jwt.encode({"user": name}, SECRET, algorithm="HS256")
    data = {"session": session}
    return jsonify(data)


@app.route('/login', methods=["POST"])
def login():
    if g.user:
        data = {"error": "User already logged in."}
        return jsonify(data), 400

    name = request.json.get('name', '')
    password = request.json.get('password', '')
    user = User.query.filter_by(username=name).first() 

    if not user or not check_password_hash(user.password, password):
        data = {"error": "User does not exist"}
        return jsonify(data), 400
    
    session = jwt.encode({"user": name}, SECRET, algorithm="HS256")
    data = {"session": session}
    return jsonify(data)

@app.route('/chat_messages', methods=["POST"])
def chat_get():
    if not g.user:
        data = {"error": "No user logged in."}
        return jsonify(data), 400
    
    try:
        chat_id = request.json.get('chat_id', '')
        chat = Chatroom.query.filter(
            and_(
                Chatroom.id==chat_id,
                Chatroom.users.any(User.username == g.user.username)
            )
        ).first()
    except Exception as e:
        app.logger.error(e)
        data = {"error": "Something went wrong."}
        return jsonify(data), 400

    if not chat:
        data ={"error":"There is no chat with this ID you are allowed to see."}
        return jsonify(data), 400

    messages = [{"user": m.user.username, "content": m.content} for m in chat.messages]
    data = {"data": messages}
    return jsonify(data)

@app.route('/chat', methods=["POST"])
def chat_post():
    if not g.user:
        data = {"error": "No user logged in."}
        return jsonify(data), 400
    
    guest = request.json.get('guest', '')
    guest_user = User.query.filter_by(username=guest).first() 
    
    if not guest_user:
        data = {"error": "No such guest user exists."}
        return jsonify(data), 400

    try:
        chat = Chatroom()
        g.user.chatrooms.append(chat)
        guest_user.chatrooms.append(chat)
        db.session.commit()
    except Exception as e:
        app.logger.error(e)
        data = {"error": "Something went wrong."}
        return jsonify(data), 400


    data = {"data": chat.id}
    return jsonify(data)


@app.route('/message', methods=["POST"])
def message():
    if not g.user:
        data = {"error": "No user logged in"}
        return jsonify(data), 400
    
    message = request.json.get('message', '')
    chat_id = request.json.get('chat_id', '')
    chat = Chatroom.query.filter_by(id=chat_id).first()

    if not chat:
        data = {"error": "No such chat exists."}
        return jsonify(data), 400

    if g.user not in chat.users:
        data = {"error": "There is no chat with this ID you are allowed to see."}
        return jsonify(data), 400
    
    try:
        message = Message(content=message)
        db.session.add(message)
        chat.messages.append(message)
        g.user.messages.append(message)
        db.session.commit()
    except Exception as e:
        app.logger.error(e)
        data = {"error": "Something went wrong."}
        return jsonify(data), 400

    data = {"data": message.id}
    return jsonify(data)

@app.route('/users', methods=["GET"])
def getUsers():
    if not g.user:
        data = {"error": "No user logged in"}
        return jsonify(data), 400

    users = User.query.all()
    data = {"users": [ {
        "id": user.id,
        "username": user.username
    } for user in users]}
    return jsonify(data)

@app.route('/me', methods=["GET"])
def user_me():
    if not g.user:
        data = {"error": "No user logged in"}
        return jsonify(data), 400

    chats = [{'id': cr.id} for cr in g.user.chatrooms]
    data = {"data": chats}
    return jsonify(data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
