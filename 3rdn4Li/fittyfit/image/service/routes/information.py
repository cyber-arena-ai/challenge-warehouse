from app  import app
from flask import render_template, redirect, g

""" This file contains all routes to the information pages.
"""

@app.route("/")
@app.route("/index")
def index():
    if g.user:
        return redirect("/home")
    return render_template("index.html")
    
@app.route("/trainers")
def trainers():
    names = ["Sara", "Bob", "Andrew", "Jim", "Cornelia", "Julia", "Gloria", "Ramin", "Marty", "Sven", "George", "Patricia"]
    trainers = [{"id": f"{i:02}", "name": n} for i, n in enumerate(names)]
    return render_template("trainers.html", trainers=trainers)
    
@app.route("/course/<cid>")
def course(cid):
    if cid not in ["1", "2", "3"]:
        return redirect("/")
    return render_template("course.html", cid=cid)
    
@app.route("/prices")
def prices():
    return render_template("prices.html")