from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from app1.project_3.templates.models import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)


class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')


@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Пользователь с таким логином уже существует"
            return render_template('register.html', title='Регистрация', form=form, error=error)

        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('registration.html', title='Регистрация', form=form)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class ReviewForm(FlaskForm):
    review = StringField('Отзыв', validators=[DataRequired()])
    submit = SubmitField()


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            return redirect('/skiing_info')
        else:
            error = 'Неверный логин или пароль'
            return render_template('login.html', title='Авторизация', form=form, error=error)

    return render_template('login.html', title='Авторизация', form=form)


@app.route('/skiing_info')
def skiing_info():
    return render_template('skiing.html')


@app.route('/skiing_image', methods=['GET', 'POST'])
def skiing_image():
    form = ReviewForm()
    if form.validate_on_submit():
        return redirect('/skiing_info')
    return render_template('skiing_image.html', form=form)


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
