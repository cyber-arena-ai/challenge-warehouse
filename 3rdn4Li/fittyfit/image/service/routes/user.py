from app  import app
from flask import request, render_template, redirect, session, g, flash
from models import db, User, Report
from helper import totp, generate_key
from pikepdf import Pdf
import shutil
import hashlib
import uuid
import os

""" This file contains all routes to user related pages.
"""

@app.route('/register', methods=['GET', 'POST'])
def register():      
    # Register a new user
    if g.user:
        return redirect("/home")

    # TODO Check for admin

    if request.method == 'POST':
        # Check form
        if 'name' not in request.form:
            flash("You must provide a user name.", "red")
            return render_template("register.html")

        n = request.form['name']

        # Check length of username
        if len(n) < 4:
            flash("Your name must contain at least four characters.", "red")
            return render_template("register.html")
        
        # Check if user already exsits
        if User.query.filter_by(name=n).count() > 0:
            flash("User with this name does already exist.", "red")
            return render_template("register.html")

        # Generate key
        seed, key = generate_key(n) 

        # Create user directory
        hash = hashlib.md5(uuid.uuid4().bytes).hexdigest()   
        user_dir = os.path.join(app.config['NFT_FOLDER'], n, hash)     
        os.makedirs(user_dir, exist_ok=True)
        shutil.copyfile("./nft.pdf", os.path.join(user_dir, "nft.pdf"))

        # Create user
        user = User(name=n, seed=seed, hash=hash)
        db.session.add(user)
        db.session.commit()
        
        return render_template("register.html", key=key)

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Login a new user
    if g.user:
        return redirect("/home")

    if request.method == 'POST':       
        # Check form
        if 'name' not in request.form:
            flash("You must provide a user name.", "red")
            return render_template("login.html")
        
        if 'pass' not in request.form:
            flash("You must provide a password.", "red")
            return render_template("login.html")

        n = request.form['name'] 
        p = request.form['pass']

        # Check if user exists
        user = User.query.filter_by(name=n).first()
        if not user:
            flash("Your username or password are incorrect.", "red")
            return render_template("login.html")

        # Generate and check password
        _, key = generate_key(n, seed=user.seed)
        passwords = [totp(key)]
        passwords.append(totp(key, past=1))
        passwords.append(totp(key, past=2))

        if p not in passwords:
            flash("Your username or password are incorrect.", "red")
            return render_template("login.html")

        # Set session
        session['user_id'] = user.user_id
        return redirect("/home")
    return render_template("login.html")

@app.route('/logout')
def logout():
    # Log the user out
    session.clear()
    return redirect("/")

@app.route('/home')
def home():         
    # The home of the user that list all their training plans
    if not g.user:
        return redirect("/")    
        
    # Admins see a list of the damaged files to review them
    dir = "damaged" if g.user.admin else os.path.join(g.user.name, g.user.hash)

    # Prepare the list of NFTs
    nfts = []  
    for f in os.listdir(os.path.join(app.config['NFT_FOLDER'], dir)):
        file_path = os.path.join(app.config['NFT_FOLDER'], dir, f)
        
        nft = Pdf.open(file_path)           
        meta = nft.open_metadata()
        
        # Check if NFT was reported
        report = Report.query.filter_by(name=f).first()

        nft = {
            "name": f,
            "data": os.path.join(dir, f),        
            "creator": meta["pdf:creator"],
            "description": meta["pdf:description"],    
            "score": meta["pdf:score"],
            "level": meta["pdf:level"],    
            "part": meta["pdf:part"],
            "owner": meta["pdf:owner"],
            "report": report is not None
        }

        nfts.append(nft)
            
    return render_template("home.html", nfts=nfts)
