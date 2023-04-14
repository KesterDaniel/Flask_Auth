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

login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# User loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, str(user_id))


# fetching user and checking password match
def get_user(email, password):
    """
    email and password refers to the data in the login form
    which will be used to find the user in the database
    returns None no user is found
    """
    user = User.query.filter_by(email=email).first()
    password_match = check_password_hash(user.password, password)
    if user is not None and password_match:
        return user
    return None


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
            flash("Email already in use. Login instead?")
            return redirect(url_for(request.endpoint))
        login_user(new_user)
        return redirect(url_for("secrets"))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        user = get_user(request.form["email"], request.form["password"])
        if user is not None:
            login_user(user)
            return redirect(url_for("secrets"))
        else:
            flash("Unable to login. Invalid credentials!")
            return redirect(url_for(request.endpoint))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    app.config['UPLOAD_FOLDER'] = "./static/files"
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
