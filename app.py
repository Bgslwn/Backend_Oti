from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class StudentModel(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String())
    last_name = db.Column(db.String())
    email = db.Column(db.String())
    gender = db.Column(db.String())
    divisi = db.Column(db.String())

    def __init__(self, first_name, last_name, email, gender, divisi):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.gender = gender
        self.divisi = divisi

    def __repr__(self):
            return f"{self.first_name}:{self.last_name}"

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/home', methods=['GET', 'POST'])
@login_required
def dashboard():
    students = StudentModel.query.all()
    return render_template('dashboard.html', students = students)

@app.route('/list', methods=['GET', 'POST'])
@login_required
def List():
    students = StudentModel.query.all()
    return render_template('index.html', students = students)    


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return render_template('logout.html')


@ app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.before_first_request
def create_table():
    db.create_all()

@app.route('/create', methods = ['GET','POST'])
@login_required
def create():
    if request.method == 'GET':
        return render_template('create.html')
    
    if request.method == 'POST':
        division = request.form.getlist('divisi')
        divisi=",".join(map(str, division))
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        gender = request.form['gender']
        divisi = divisi

        student = StudentModel(
            first_name=first_name,
            last_name=last_name,
            email=email,
            gender=gender,
            divisi=divisi
        )
        db.session.add(student)
        db.session.commit()
        return redirect('/home')

@app.route('/<int:id>/edit', methods=['GET',"POST"])
@login_required
def update(id):
    student = StudentModel.query.filter_by(id=id).first()
    if request.method == 'POST':
            db.session.delete(student)
            db.session.commit()
            if student:
                division = request.form.getlist('divisi')
                divisi=",".join(map(str, division))
                first_name = request.form['first_name']
                last_name = request.form['last_name']
                email = request.form['email']
                gender = request.form['gender']
                divisi = divisi

                student = StudentModel(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    gender=gender,
                    divisi=divisi
            )
            db.session.add(student)
            db.session.commit()
            return redirect('/list')
            return f"Student with id = {id} Does not exist"

    return render_template('update.html', student = student)


@app.route('/<int:id>/delete', methods=['GET','POST'])
@login_required
def delete(id):
    students = StudentModel.query.filter_by(id=id).first()
    if request.method == 'POST':
        if students:
            db.session.delete(students)
            db.session.commit()
            return redirect('/list')
        #abort(404)
        else:
            return redirect('/list')

    return render_template('delete.html')

if __name__ == "__main__":
    app.run(debug=True)