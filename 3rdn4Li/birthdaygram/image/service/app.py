from flask import Flask, request, render_template, make_response, redirect
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv, dotenv_values
import uuid
import hashlib
import logging
import jwt
from functools import wraps
from PIL import Image
import io
import base64
import time

MAX_IMAGE_SIZE = 3_000_000

load_dotenv() 
app = Flask(__name__)
# CyberArena packaging deviation: SQLite instead of the external Postgres
# container, so the challenge ships as one self-contained vulbox (SOP §4).
# Models use only portable column types; gameplay/vuln surface (stego images)
# is unchanged. Relative path resolves under the app dir.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URI") or "sqlite:///birthdaygram.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

secret = os.getenv("SECRET")

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(32), unique=True)
    password = db.Column(db.String(32))
    profileImg = db.Column(db.String(MAX_IMAGE_SIZE))
    timestamp = db.Column(db.Integer)

    def __repr__(self):
        return f"Id: {self.id}, Username: {self.username}, Password: {self.password}, Img: {self.profileImg}"

class Images(db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    image = db.Column(db.String(MAX_IMAGE_SIZE))
    public = db.Column(db.Boolean, unique=False, default=True)
    creator_name = db.Column(db.String(32))
    timestamp = db.Column(db.Integer)

    def __repr__(self):
        return f"Id: {self.id}, Creator ID: {self.creator_name}, Public: {self.public}, Img: {self.image}"

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(255))
    creator_name = db.Column(db.String(32))
    timestamp = db.Column(db.Integer)

    def __repr__(self):
        return f"Id: {self.id}, Image ID: {self.image}, Comment: {self.comment}, Creator ID: {self.creator_name}"

def is_logged_in(r):
    @wraps(r)

    def check_login(*args, **kwargs):
        cookie = request.cookies.get("session")
        if cookie:
            try:
                user = jwt.decode(cookie, secret, algorithms=["HS256"])
                user = User.query.filter(User.username == user.get("name")).first()
                if not user:
                    return redirect("/auth/login")
            except:
                return redirect("/auth/login")
            return r(*args, **kwargs)
        else:
            return redirect("/auth/login")

    return check_login

@app.route('/')
def home():
    return render_template('index.html', cookie=hasCookie(request))

@app.route('/auth/register', methods=['POST', 'GET'])
def user_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            try:
                id = str(uuid.uuid4())
                user = User(id=id, username=username, password=password, profileImg="", timestamp=int(time.time()))
                db.session.add(user)
                resp = make_response(redirect("/auth/login"))
                db.session.commit()
                return resp
            except:
                return "Unable to create user!", 400
    else:
        return render_template('register.html', cookie=hasCookie(request))

@app.route('/auth/login', methods=['POST', 'GET'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            try:
                user_query = User.query.filter(User.username == username, User.password == password).with_entities(User.username)
                if user_query.count() != 0:
                    token = jwt.encode({"name": user_query.one()[0]}, secret, algorithm="HS256")
                    resp = make_response(redirect("/"))
                    resp.set_cookie("session", token) 
                    return resp
                else:
                    return "Couldnt log you in.", 400
            except:
                return "Error", 500
    else:
        return render_template('login.html', cookie=hasCookie(request))

@app.route('/auth/logout')
@is_logged_in
def logout():
    cleanUp()
    resp = make_response(redirect("/"))
    resp.delete_cookie('session')
    return resp

@app.route('/profile', methods=['GET'])
@is_logged_in
def profile():
    return render_template('profile.html', cookie=hasCookie(request))

@app.route('/view/<username>', methods=['GET'])
def view(username):
    try:
        is_self = False
        cookie = request.cookies.get("session") 
        try:
            c_username = jwt.decode(cookie, secret, algorithms=["HS256"])
            if c_username.get("name") == username:
                is_self = True
        except:
            is_self = False
        user = User.query.filter(User.username == username).first() 
        images = Images.query.filter(Images.creator_name == user.username).all()
    except:
        return "User not found", 500
    return render_template('view.html', images=images, user=user, cookie=hasCookie(request), is_self=is_self)    

@app.route('/updateProfile/<attribute>', methods=['POST'])
@is_logged_in
def update_profile(attribute):
    cookie = request.cookies.get("session") 
    try: 
        username = jwt.decode(cookie, secret, algorithms=["HS256"])
    except:
        return redirect("/auth/login")
    username = username.get("name")
    if attribute == "image": 
        image = request.files['image'].read()
        if (not image) or len(image) > MAX_IMAGE_SIZE:
            return "Inacceptable image size", 400
        try:
            image = imageToStr(image)
        except:
            return "Wrong Image encoding", 400
        try:
            user = User.query.filter(User.username == username).first()
            user.profileImg = image
            db.session.commit()
            return redirect("/profile")
        except:
            return "Error", 500

    elif attribute == "username":
        new_username = request.form['username']
        old_password = request.form['old_password'] 
        if not new_username or not old_password:
            return "Error", 500
        resp = make_response(redirect("/profile"))
        try:
            user = User.query.filter(User.username == username).first() 
            if user.password != old_password:
                return "Error", 500
            user.username = new_username
            token = jwt.encode({"name": new_username}, secret, algorithm="HS256")
            resp.set_cookie("session", token)
            db.session.commit()
            return resp
        except:
            make_response("Couldnt change username", 500)
        return resp
    elif attribute == "password":
        new_password = request.form['password']
        old_password = request.form['old_password']        
        if not new_password or not old_password:
            return "Missing Argument", 500
        try:
            user = User.query.filter(User.username == username).first()
            if user.password != old_password:
                return "Not your old password", 500
            user.password = new_password
            db.session.commit()
            return redirect("/profile")
        except:
            return "Error", 500
    return "Unknown Attribute", 400

@app.route("/feed", methods=['GET'])
def feed():
    try:
        images = Images.query.filter(Images.public == True).order_by(Images.timestamp.desc()).limit(20).all()
        return render_template("feed.html", images=images, cookie=hasCookie(request))
    except:
        return "Error with fetching the feed Images", 500

@app.route("/upload", methods=['GET', 'POST'])
@is_logged_in
def upload():
    cookie = request.cookies.get("session") 
    if request.method == 'GET':
        return render_template('upload.html', cookie=hasCookie(request))
    else: 
        image = request.files['image'].read()
        vis = request.form['public']
        if (not image) or len(image) > MAX_IMAGE_SIZE:
            return "Inacceptable image size", 400
        if not vis:
            return "Missing visibility", 400
        try:
            image = imageToStr(image)
        except:
            return "Wrong Image encoding", 400
        if vis == "public":
            vis = True
        else:
            vis = False
        try: 
            username = jwt.decode(cookie, secret, algorithms=["HS256"])
        except:
            return redirect("/auth/login", 301)
        try:
            db_image = Images(image=image, public=vis, creator_name=username.get("name"), timestamp=int(time.time())) 
            db.session.add(db_image)
            db.session.commit()
            return redirect(f"/view/{username.get('name')}")
        except:
            return "Error", 500

@app.route("/image/<id>", methods=['GET', 'POST'])
def image(id):
    try:
        image = Images.query.filter(Images.id == id).first()
        if not image:
            return "Couldnt find the image"
    except:
        return "Error fetching the image", 500
    if request.method == 'GET':
        if image.public == True:
            comments = Comments.query.filter(Comments.image == image.id).all()
            return render_template('image.html', image=image, comments=comments, cookie=hasCookie(request))
        else: 
            try: 
                cookie = request.cookies.get("session")    
                username = jwt.decode(cookie, secret, algorithms=["HS256"])
            except:
                return redirect("/auth/login")
            username = username.get("name")
            if username:
                comments = Comments.query.filter(Comments.image == image.id).all()
                if image.creator_name == username:
                    return render_template('image.html', image=image, comments=comments, cookie=hasCookie(request))
                else:
                    return "This is a private Image"
            else:
                return redirect("/auth/login")
    else:
        if request.cookies.get("session"):
            comment = request.form['comment']
            cookie = request.cookies.get("session")    
            try: 
                username = jwt.decode(cookie, secret, algorithms=["HS256"])
            except:
                return redirect("/auth/login")
            try:
                comment = Comments(image=id, comment=comment, creator_name=username.get("name"), timestamp=int(time.time()))
                db.session.add(comment)
                db.session.commit()
                comments = Comments.query.filter(Comments.image == image.id).all()
                return render_template('image.html', image=image, comments=comments, cookie=hasCookie(request))
            except:
                return "Error", 500
        else:
            return redirect("/auth/login")

def imageToStr(image):
    wrongType = checkExifData(image)
    if not wrongType:
        return wrongType
    image = str(base64.b64encode(image))[2:-1]
    return image

def checkExifData(image):
    pilImage = Image.open(io.BytesIO(image))
    if pilImage.format != "PNG":
        return False
    return True

def hasCookie(request):
    if request.cookies.get('session'):
        return True
    return False

def cleanUp():
    cur_time = int(time.time())
    User.query.filter(User.timestamp < (cur_time - 15*60)).delete()
    Comments.query.filter(Comments.timestamp < (cur_time - 15*60)).delete()
    Images.query.filter(Images.timestamp < (cur_time - 15*60)).delete()
    db.session.commit()

# CyberArena packaging: upstream created tables only under `python app.py`.
# We serve via gunicorn (app:app), so create the schema at import too.
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    LAST_CLEAR = int(time.time())
    with app.app_context():
        db.create_all()
    app.run(host="::", port=3000, debug=False)
