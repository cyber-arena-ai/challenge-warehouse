# encoding=utf8  
from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import make_response

from flask_sqlalchemy import SQLAlchemy

import datetime
import socket 
import uuid
import hashlib
import base64
import ed25519
import json
import string
import random
import re
import ipaddress

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
import os as _os  # CyberArena: sqlite collapse (upstream shipped this commented)
app.config['SQLALCHEMY_DATABASE_URI'] = _os.getenv('DB_URI') or 'sqlite:///marscasino.db'
db = SQLAlchemy(app)

PRIZE_COST = 500
MAX_COINS = 100000

# ================================================
# === MODELS =====================================
# ================================================

class PrizeModel(db.Model):
    __tablename__ = 'prize'

    prize_id = db.Column(db.VARCHAR(length=36), primary_key=True)
    prize = db.Column(db.VARCHAR(length=36))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class VoucherModel(db.Model):
    __tablename__ = 'voucher'

    voucher_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    active = db.Column(db.Boolean, default=True)

class KeyModel(db.Model):
    __tablename__ = 'key'
    key = db.Column(db.VARCHAR(length=12), primary_key=True)
    created = db.Column(db.DateTime)

class UserModel(db.Model):
    __tablename__ = 'user'

    username = db.Column(db.VARCHAR(length=36), primary_key=True)
    password = db.Column(db.VARCHAR(length=36))
    ip = db.Column(db.VARCHAR(length=12))
    code = db.Column(db.VARCHAR(length=36))
    created = db.Column(db.DateTime)
    session = db.Column(db.VARCHAR(length=36), default="")
    active = db.Column(db.Boolean, default=False)
    coins = db.Column(db.Integer, default=10)
    recruited_by = db.Column(db.VARCHAR(length=36))
    fcode = db.Column(db.VARCHAR(length=32))
    item = db.Column(db.VARCHAR(length=32), default="")
    item_cost = db.Column(db.Integer, default=0)
    items_sold = db.Column(db.Integer, default=0)
    item_sold_ts = db.Column(db.DateTime, default=datetime.datetime(2020,1,1) )

    def __repr__(self):
        return f"<{self.username}>"

# ================================================
# === UTILS ======================================
# ================================================

def check_user():
    s = request.cookies.get('session')
    return UserModel.query.filter_by(session=s).first()

def clean_inactive_user():
    ts = datetime.datetime.now() - datetime.timedelta(minutes=5)
    users = UserModel.query.filter_by(active=False).filter(UserModel.created < ts).delete()
    db.session.commit()

def create_key():
    ts = datetime.datetime.now() - datetime.timedelta(minutes=2)
    key = KeyModel.query.filter(KeyModel.created > ts).first()
    if not key:
        k = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation )\
                for n in range(12)])
        key = KeyModel(created=datetime.datetime.now(), key=k)
        db.session.add(key)
        db.session.commit()

def add_coins(user, coins):
    if user.coins + coins > MAX_COINS:
        return "You reached the maximum amount of coins. Go and buy some prizes."
    user.coins += coins
    db.session.commit()
    return ""

def remove_coins(user, coins):
    if user.coins - coins < 0:
        return "You have not enough coins."
    user.coins -= coins
    db.session.commit()
    return ""

# ================================================
# === VIEWS ======================================
# ================================================

@app.route("/")
def index_view():
    user = check_user()
    return render_template('index.html', title='Mars Casino', user=user)

@app.route("/register", methods = ['GET', 'POST'])
def register_view():
    user = check_user()
    if user:
        return redirect("/home")

    if request.method == 'POST':
        create_key()
        clean_inactive_user()
        username = request.form['username']
        fcode = hashlib.md5(username.encode()).hexdigest()
        password = request.form['password']
        ip = request.form['ip']

        try:
            ipaddress.ip_address(ip)
        except:
            return render_template('register.html', title='Register', error="Your IP is not valid")

        rec_code = request.form['fcode']
        error = ""

        user = UserModel.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', title='Register', error="User already exists")

        code = uuid.uuid4()
        url = f"http://{request.host}/verify?code={code}"
        print(url)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, 1337))
            s.send(url.encode())
        except Exception as e:
            print(e)
            error = f"Sending {code} failed"

        ts = datetime.datetime.now()
        user = UserModel(username=username, password=password, ip=ip,
                code=str(code), recruited_by=rec_code, fcode=fcode, created=ts)
        db.session.add(user)

        if rec_code:
            recruiter = UserModel.query.filter_by(fcode=rec_code).first()
            if recruiter:
                user.coins = 50
                # number of recruited minus current one 
                number_of_rec = UserModel.query.filter_by(recruited_by=rec_code)\
                        .filter(UserModel.username!=username).count()
                # recruiter used all friend codes 
                if number_of_rec < 3:
                    add_coins(recruiter, 50)

        db.session.commit()

        return render_template('register.html', title='Register', username=username, ip=ip, error=error)

    return render_template('register.html', title='Register')

@app.route("/verify")
def verify_view():
    clean_inactive_user()
    code = request.args.get('code')
    user = UserModel.query.filter_by(code=code).first()
    if not user:
        return redirect("/register")

    user.active = True
    db.session.commit()

    return redirect("/")

@app.route("/login", methods = ['GET', 'POST'])
def login_view():
    user = check_user()
    if user:
        return redirect("/home")

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserModel.query.filter_by(username=username).first()
        if not user or user.password != password:
            error = "Wrong username or password"
        elif not user.active:
            error = "Account is not activated"
        else:
            s = str(uuid.uuid4())
            user.session = s
            db.session.commit()
            res = make_response(redirect("/home"))
            res.set_cookie('session', s)
            return res
        return render_template('login.html', title='Login', error=error)
    return render_template('login.html', title='Login')

@app.route("/logout")
def logout_view():
    res = make_response(redirect("/"))
    res.set_cookie('session', '', expires=0)
    return res

@app.route("/delete-account", methods = ['GET', 'POST'])
def delete_view():
    user = check_user()
    if not user:
        return redirect("/")

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserModel.query.filter_by(username=username).first()
        if user.password != password:
            error = "Wrong password"
            return render_template('delete.html', title='Delete', error=error, user=user)
        db.session.delete(user)
        db.session.commit()
        return redirect("/logout")
    return render_template('delete.html', title='Delete', user=user)

@app.route("/home", methods = ['GET', 'POST'])
def home_view():
    user = check_user()
    if not user:
        return redirect("/")

    if request.method == 'POST':
        item = request.form['item']
        item_cost = request.form['item_cost']
        if not item or not item_cost or not item_cost.isdigit():
            error = "invalid arguments"
            return render_template('home.html', title='Home', user=user, error=error)
        user.item = item
        user.item_cost = item_cost
        db.session.commit()
    
    return render_template('home.html', title='Home', user=user)

@app.route("/recruite")
def recrutie_view():
    user = check_user()
    if not user:
        return redirect("/")

    return render_template('recruite.html', title='Friends', user=user)

@app.route("/buy", methods = ['GET', 'POST'])
def buy_view():
    user = check_user()
    if not user:
        return redirect("/")
    
    users = UserModel.query.filter(UserModel.item != "").all()

    item = None
    item_owner = request.args.get('u')
    owner = UserModel.query.filter_by(username=item_owner).first()
    if owner:
        error = remove_coins(user, owner.item_cost)
        if len(error) > 0:
            return render_template('buy.html', title='Mars Casino', user=user, users=users, error=error)
        item = owner.item

        # bot protection. we do not expect items to be sold more than once per minute
        ts = datetime.datetime.now() - datetime.timedelta(minutes=5)
        if owner.item_sold_ts < ts or owner.items_sold == 0:
            add_coins(owner, owner.item_cost)
            owner.item_sold_ts = datetime.datetime.now()
            owner.items_sold += 1
            db.session.commit()

    return render_template('buy.html', title='Mars Casino', user=user, users=users, item=item)

@app.route("/payout", methods = ['GET', 'POST'])
def payout_view():
    user = check_user()
    if not user:
        return redirect("/")

    if request.method == 'POST':
        amount = request.form['amount']
        prize_id = request.form['id']
        if not amount.isdigit():
            error = "Amount not valid"
            return render_template('payout.html', title='Mars Casino', user=user, error=error)
        error = remove_coins(user, amount)
        if len(error) > 0:
            return render_template('payout.html', title='Mars Casino', user=user, error=error)
        number = int(amount / PRIZE_COST)

        if prize_id:
            prizes = PrizeModel.query.filter_by(prize_id=prize_id).all()
        else:
            prizes = PrizeModel.query.order_by(PrizeModel.created.desc()).limit(number)
        return render_template('payout.html', title='Mars Casino', user=user,prizes=prizes)
    
    return render_template('payout.html', title='Mars Casino', user=user)

# simple roulette
@app.route("/game1", methods = ['GET', 'POST'])
def game1_view():
    user = check_user()
    if not user:
        return redirect("/")

    black = list(range(1, 36, 2))
    red = list(range(2,37,2))
    first = [1,4,7,10,13,16,19,22,25,28,31,34]
    second = [2,5,8,11,14,17,20,23,26,29,32,35]
    third = [3,6,9,12,15,18,21,24,27,30,33,36]
    answers = ["red","black","first","second","third"]
    answers += ["%d" % i for i in range(0,36)]

    if request.method == 'POST':
        bet = request.form['bet']
        field = request.form['field']
        if field not in answers or not bet.isdigit():
            error = "Input not valid"
            return render_template('game1.html', title='Game', user=user, error=error)
        bet = int(bet)

        error = remove_coins(user, bet)
        if len(error) > 0:
            return render_template('game1.html', title='Game', user=user, error=error)

        field = field.lower()
        number = random.randint(0,36) 
        if field == "red" and number in red:
            win = bet
        elif field == "black" and number in black:
            win = bet
        elif field == "first" and number in first:
            win = bet * 2
        elif field == "second" and number in second:
            win = bet * 2
        elif field == "third" and number in third:
            win = stack * 2
        elif field.isdigit() and int(field) == 0:
            win = bet * 36
        elif field.isdigit() and int(field) == number:
            win = bet * 35
        else:
            win = 0
        error = add_coins(user, win)
        if len(error) > 0:
            return render_template('game1.html', title='Game', user=user, error=error)
        db.session.commit()
        return render_template('game1.html', title='Game', user=user, win=win, number=number)
    return render_template('game1.html', title='Game', user=user)

@app.route("/game2", methods = ['GET', 'POST'])
def game2_view():
    create_key()
    user = check_user()
    if not user:
        return redirect("/")
     
    if request.method == 'POST':
        bet = request.form['bet']
        if not bet or not bet.isdigit() or int(bet) <= 0:
            error = "Your bet is not valid"
            return render_template('game2.html', title='Game', user=user, error=error)
        bet = int(bet)

        error = remove_coins(user, bet)
        if len(error) > 0:
            return render_template('game2.html', title='Game', user=user, error=error)

        ts = datetime.datetime.now().replace(microsecond=0)
        key = KeyModel.query.filter(KeyModel.created <= ts)\
                    .order_by(KeyModel.created.desc()).first() 
        key = key.key
        value = random.randint(0, int(1.3 * bet))

        v_model = VoucherModel()
        db.session.add(v_model)
        db.session.commit()

        code = f"{user.username};{value};{v_model.voucher_id}"

        res = ""
        for i, c in enumerate(code):
            res += chr(ord(c) ^ ord(key[i%len(key)]))
        
        vdata = {"ts":ts.strftime('%s'), "code":res.encode().hex()}

        voucher = base64.b64encode(json.dumps(vdata).encode())
        db.session.commit()
        return render_template('game2.html', title='Game', user=user, voucher=voucher.decode())
    return render_template('game2.html', title='Game', user=user)

@app.route("/voucher", methods = ['GET', 'POST'])
def voucher_view():
    create_key()
    user = check_user()
    if not user:
        return redirect("/")

    if request.method == 'POST':
        voucher = request.form['voucher']
        try:
            vdata = json.loads(base64.b64decode(voucher))
        except:
            error = "Your code is invalid"
            return render_template('voucher.html', title='Voucher', user=user, error=error)
            
        ts = datetime.datetime.fromtimestamp(int(vdata['ts']))
        key = KeyModel.query.filter(KeyModel.created <= ts)\
                .order_by(KeyModel.created.desc()).first() 
        key = key.key
        res = ""
        for i, c in enumerate(bytes.fromhex(vdata['code'])):
            res += chr(c ^ ord(key[i%len(key)]))
        res = res.split(';')
        
        v_model = VoucherModel.query.filter_by(voucher_id=res[2]).first()
        if not v_model or not v_model.active:
            error = "This voucher was already used"
            return render_template('voucher.html', title='Voucher', user=user, error=error)
        if res[0] == user.username:
            error = add_coins(user, int(res[1]))
            if len(error) > 0:
                return render_template('voucher.html', title='Voucher', user=user, error=error)
            v_model.active = False
            db.session.commit()
        return render_template('voucher.html', title='Voucher', user=user, win=res[1])

    return render_template('voucher.html', title='Voucher', user=user)

@app.route("/donation")
def give_money_view():
    vk = ed25519.VerifyingKey(base64.b64decode(b'Dx85Piu9YYnySaPFa6yzrvy63HkzkscevAWTk1JVMxA='))
    payload = request.args.get('p')
    sig = request.args.get('s').replace(' ', '+')
    
    try:
        vk.verify(sig.encode(), payload.encode(), encoding="base64")
        user = payload.split(';')[0]
        amt = payload.split(';')[1]
        ip = payload.split(';')[2]
        
        if ip != request.host.replace("[","").split("]")[0]:
            return "fail"

        user = UserModel.query.filter_by(username=user).first()
        user.coins += int(amt)
        db.session.commit()
    except ed25519.BadSignatureError:
        return "fail"
    return "ok"

# CyberArena: create schema at import (served via gunicorn)
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    db.create_all()
    create_key()
    app.run(host='0.0.0.0')
