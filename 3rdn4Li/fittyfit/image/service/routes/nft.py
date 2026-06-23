from app  import app
from flask import request, render_template, redirect, g, jsonify, flash, send_from_directory, send_file
from werkzeug.utils import secure_filename
from models import db, User, Report
from helper import  nft_transfer
from urllib.parse import unquote
import filetype
import zipfile
import os

""" This file contains all paths related to the Non Fungible Trainingsplan business 
"""

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if not g.user:
        return redirect("/")

    if request.method == 'POST':        

        if not 'step' in request.form:
            flash("No step in your request", "red")
            return render_template("generate.html", step="upload")
        step = request.form['step']

        # UPLOAD
        if step == "upload":      
            # TODO check file type              
            # check various file things
            if 'file' not in request.files:
                flash("No file in your request", "red")
                return render_template("generate.html", step="upload")
            file = request.files['file']

            print(file)

            if not file.filename or file.filename == '':
                flash("No filename in your request", "red")
                return render_template("generate.html", step="upload")

            kind = filetype.guess(file.stream.read())
            file.stream.seek(0)
            
            if os.path.splitext(file.filename)[1] != '.pdf' or \
                    kind is None or kind.mime != 'application/pdf':
                flash("File must be a PDF", "red")
                return render_template("generate.html", step="upload")

            filename = secure_filename(file.filename)

            # Store file for generator
            path = os.path.join(app.config['NFT_FOLDER'], "generator", filename)
            file.save(path)
            return render_template("generate.html", step="generate", filename=filename)
            
        # GENERATE
        elif step == "generate":      
            # check request form      
            if not 'creator' in request.form or \
               not 'description' in request.form or \
               not 'score' in request.form or \
               not 'level' in request.form or \
               not 'part' in request.form or \
               not 'filename' in request.form:
                flash("Request is not complete. Creator, Description, Score, Level, Part or Filename is missing.", "red")
                return render_template("generate.html", step="upload")

            filename = request.form['filename']  

            infos = {
                "description": request.form['description'],
                "score": request.form['score'],
                "level": request.form['level'],
                "part": request.form['part'],
                "creator": request.form['creator']
            }

            # Generate NFT
            path1 = os.path.join(app.config['NFT_FOLDER'], "generator", filename)
            path2 = os.path.join(app.config['NFT_FOLDER'], g.user.name, g.user.hash, filename)   

            succ = nft_transfer(app.config['NFT_FOLDER'], path1, path2, g.user.name, infos)
            if not succ:
                return render_template("generate.html", step="upload")

            flash("You succesfully generated your NFT :)", "green")
            return render_template("generate.html", step="done")     

        return render_template("generate.html", step="upload")
    return render_template("generate.html", step="upload")

@app.route('/transfer', methods=['POST'])
def transfer():         
    # Transfer NFT from one user to another
    if not g.user:
        return redirect("/")  

    # Check form
    if 'filename' not in request.form:        
        flash("Your must provide an NFT.", "red")
        return "Error", 403
    if 'receiver' not in request.form:        
        flash("Your must provide a receiver.", "red")
        return "Error", 403

    filename = request.form['filename']
    receiver = request.form['receiver']

    # Check user
    recv_user = User.query.filter_by(name=receiver).first()
    if not recv_user:    
        flash("The user %s does not exist." % receiver, "red")
        return "Error", 403

    # Transfer NFT
    path_send = os.path.join(app.config['NFT_FOLDER'], g.user.name, g.user.hash, filename)
    path_recv = os.path.join(app.config['NFT_FOLDER'], recv_user.name, recv_user.hash, filename)

    succ = nft_transfer(app.config['NFT_FOLDER'], path_send, path_recv, receiver)
    if not succ:
        return "Error", 403

    flash("You succesfully tranfered your NFT to %s." % receiver, "green")
    return "Ok", 200    

@app.route('/report')
def submit_report():     
    # Report a broken NFT
    if not g.user:
        return redirect("/")

    path = request.args.get('path')    
    report = Report(name=os.path.basename(path))
    db.session.add(report)
    db.session.commit()
    return "ok", 200

@app.route('/search')
def search(): 
    # Search user names for autocomplete   
    if not g.user:
        return redirect("/")

    s = f"%{request.args.get('s')}%"
    user_list = User.query.filter(User.name.like(s)).all()
    data = {}
    for u in user_list:
        data[u.name] = None
    return jsonify(data)

@app.route('/nft')
def download_nft():
    # Download one specific NFT
    if not g.user:
        return redirect("/")

    f = request.args.get('file')
    f = unquote(f)
    if ".." in f or f[0] == "/":
        flash("This path is not allowed.", "red")
        return redirect("/")
    path = os.path.abspath(os.path.join(app.config['NFT_FOLDER'], f))
    return send_from_directory(directory=os.path.dirname(path), path=os.path.basename(path))
    
@app.route('/download')
def download(): 
    # Download all NFTs as ZIP
    if not g.user:
        return redirect("/")

    dir = "damaged" if g.user.admin else os.path.join(g.user.name, g.user.hash)
    zipf = zipfile.ZipFile('nfts.zip','w', zipfile.ZIP_DEFLATED)
    for f in os.listdir(os.path.join(app.config['NFT_FOLDER'], dir)):
        file_path = os.path.join(app.config['NFT_FOLDER'], dir, f)
        zipf.write(file_path)
        if g.user.admin:
            os.remove(file_path)
    zipf.close()

    return send_file('nfts.zip',
            mimetype = 'zip',
            attachment_filename= 'nfts.zip',
            as_attachment = True)
