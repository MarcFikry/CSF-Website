import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import login_required

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///csf.db")

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
def index():
    if request.method == "GET":
        if session.get("user_id"):
            rows = db.execute(
                "SELECT * FROM users WHERE id = ?", session.get("user_id")
            )
            flash(f"Connecté en tant que {rows[0]["name1"]} {rows[0]["name2"]}")

        return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return redirect("/login")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return redirect("/login")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Nom d'utilisateur ou mot de passe invalide")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if not request.form.get("first-name"):
            return redirect("/register")

        elif not request.form.get("last-name"):
            return redirect("/register")

        elif not request.form.get("username"):
            return redirect("/register")

        elif not request.form.get("password"):
            return redirect("/register")

        elif not request.form.get("confirmation"):
            return redirect("/register")

        elif request.form.get("password") != request.form.get("confirmation"):
            flash("Mot de passe et confirmation ne sont pas similaires")
            return redirect("/register")

        userpresence = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(userpresence) == 1:
            flash("Nom d'utilisateur déjà pris")
            return redirect("/register")
        else:
            db.execute(
                "INSERT INTO users (username, hash, name1, name2) VALUES (?, ?, ?, ?)", request.form.get("username"),
                generate_password_hash(request.form.get("password")), request.form.get("first-name"), request.form.get("last-name")
            )

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
