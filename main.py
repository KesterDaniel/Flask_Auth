from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.app_context().push()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))



@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            new_user = User(
                email = request.form["email"],
                password = generate_password_hash(
                    request.form["password"],
                    method = "pbkdf2:sha256",
                    salt_length = 8 
                ),
                name = request.form["name"]
            )
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return "Sorry use a different email"
        return redirect(url_for("secrets", user=request.form["name"]))

    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/secrets/<user>')
def secrets(user):
    return render_template("secrets.html", user=user)


@app.route('/logout')
def logout():
    pass


@app.route('/download/<path:filename>')
def download(filename):
    app.config['UPLOAD_FOLDER'] = "./static/files"
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
