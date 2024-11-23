from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

app = Flask(__name__)

app.secret_key = "123"
user_db = "postgres"
host_ip = "127.0.0.1"
host_port = "5432"
database_name = "rpp_flask"
password = "123"

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{user_db}:{password}@{host_ip}:{host_port}/{database_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class users(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(30), nullable=False, unique=True)
  password = db.Column(db.String(102), nullable=False)
  name = db.Column(db.String(30), nullable=False, unique=True)

  def __repr__(self):
    return f'id:{self.id}, email:{self.email}, name:{self.name}'

@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))

@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template('index.html', name=current_user.name)
    return redirect(url_for('login'))

@app.route("/login", methods = ["GET", "POST"])
def login():
    errors = {}
    if request.method == "GET":
        return render_template("login.html")
    email_form = request.form.get("email")
    password_form = request.form.get("password")
    my_user = users.query.filter_by(email = email_form).first()
    if (email_form == '' or password_form == ''):
        errors = "Пожалуйста, заполните все поля"
        return render_template("login.html", errors=errors)
    elif my_user is not None:
        if check_password_hash(my_user.password, password_form):
            login_user(my_user, remember = False)
            return redirect(url_for('index'))
        else:
            errors = "Неправильный пароль"
            return render_template("login.html", errors=errors)
    elif my_user is None:
        errors = "Пользователя не существует"
        return render_template("login.html", errors=errors)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    errors ={}
    if request.method == "GET":
        return render_template("signup.html")
    email_form = request.form.get("email")
    password_form = request.form.get("password")
    name_form = request.form.get("name")
    isUserExist = users.query.filter_by(email = email_form,).first()
    if (email_form == '' or password_form == '' or name_form == ''):
        errors = "Пожалуйста, заполните все поля"
        return render_template("signup.html", errors=errors)
    elif isUserExist is not None:
        errors = "Пользователь уже существует"
        return render_template("signup.html", errors=errors)
    hashedPswd = generate_password_hash(password_form, method = "pbkdf2")
    newUser = users(email = email_form, password = hashedPswd, name = name_form)
    db.session.add(newUser)
    db.session.commit()
    return redirect(url_for('login'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)

    