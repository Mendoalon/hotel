from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

import sqlite3

from werkzeug.exceptions import abort


#from flask import Flask, render_template, request, redirect, url_for, flash


app = Flask(__name__)

app.config['SECRET_KEY'] = 'Esteesmimejorsecretoguardado!'

# Define la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database//basehotel.db"

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# crea la tabla de usuarios


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    # Usuario Autentificacion de los campos
    nombre = db.Column(db.String(40), nullable=False)
    apellido = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(60), unique=True)
    username = db.Column(db.String(15), unique=True)
    revisado_at = db.Column(db.DateTime())
    revisado = db.Column(db.Boolean())
    admin = db.Column(db.Boolean())
    is_admin = db.Column(db.Boolean(), unique=True)
    password = db.Column(db.String(80), nullable=False)
    cedula = db.Column(db.String(12), unique=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Campos del formulario login:
class LoginForm(FlaskForm):
    username = StringField('username', validators=[
                           InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=6, max=80)])
    remember = BooleanField('recuerdeme')


# Campos del formulario de registro:
class RegisterForm(FlaskForm):
    nombre = StringField('nombre', validators=[
                         InputRequired(), Length(min=4, max=40)])
    apellido = StringField('apellido', validators=[
                           InputRequired(), Length(min=4, max=40)])
    email = StringField('email', validators=[InputRequired(), Email(
        message='Correo invalido'), Length(max=60)])
    username = StringField('username', validators=[
                           InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=6, max=80)])
    is_admin = db.Column(db.Boolean, default=False)
    revisado = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/control')
def control():
    if not current_user.is_authenticated:
        flash('Ustede no esta logeado')
        return redirect(url_for('login'))

    if current_user.admin:
        flash('Usted es un administrador')
        return render_template('roles/rol_admin.html')

    if current_user.is_admin:
        flash('Usted es un super administrador')
        return render_template('roles/rol_super.html')

    return render_template('roles/rol_final.html')


# Para ingresar al el sistema cuando el usuario se encuentra registrado
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        # busca el usuario en la base de datos usando el campo username
        user = User.query.filter_by(username=form.username.data).first()

        # revisa que el password del usuario en la base de datos coincida con el ingresado
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)

                return redirect(url_for('control'))

                # return '<h1>Usuario correcto</h1>'
                #  lo direcciona al menu correspondiente segun el rol del usuario
                #  return redirect(url_for('fin'))

        return '<h1>Usuario o password incorrectas</h1>'
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login/login_usuario.html', form=form)


# Crear un nuevo registro de un usuario

# Registro de un usuario nuevo. Todos entran con los mismos campos y despues se les asigna roles
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegisterForm()

    if form.validate_on_submit():
        # el password es encriptado convirtiendolo en un string de 80 caracteres cifrado
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')

        # Se preprara la informacin para guardarla en la base de datos
        new_user = User(username=form.username.data, nombre=form.nombre.data,
                        apellido=form.apellido.data, email=form.email.data, password=hashed_password)

        # se guarda el nuevo usuario en la base de datos
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('login/registro_usuario.html', form=form)


@app.route('/ingresar')
@login_required
def ingresar():
    if not current_user.is_authenticated:
        flash('Please Log in as admin to delete user')
        return redirect(url_for('login'))
    if current_user.username != 'admin':
        flash('Please Log in as admin to delete user')
        return redirect(url_for('index'))

    return render_template('super/usuario_super.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


#######################################################################################

# Aqui se crea la tabla para todo nuestro proceso de CRUD de la base de datos
class Data(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(20))
    piso = db.Column(db.String(20))
    numero = db.Column(db.String(4))

    def __init__(self, tipo, piso, numero):

        self.tipo = tipo
        self.piso = piso
        self.numero = numero

# Esta es la ruta index donde vamos hacer las consultas de la base de datos


@app.route('/rooms', methods=['GET', 'POST'])
def rooms():
    all_data = Data.query.all()
    return render_template("rooms/index1.html", xrooms=all_data)


# esta es la ruta insert para agregar  habitaciones usando formas en html
@app.route('/insert1', methods=['POST'])
def insert1():

    if request.method == 'POST':

        tipo = request.form['tipo']
        piso = request.form['piso']
        numero = request.form['numero']

        my_data = Data(tipo, piso, numero)
        db.session.add(my_data)
        db.session.commit()

        flash("La habitación ha sido agregada")

        return redirect(url_for('rooms'))


# Esta es la ruta update cuando se va a modificar una habitacion
@app.route('/update1', methods=['GET', 'POST'])
def update1():

    if request.method == 'POST':
        my_data = Data.query.get(request.form.get('id'))

        my_data.tipo = request.form['tipo']
        my_data.piso = request.form['piso']
        my_data.numero = request.form['numero']

        db.session.commit()
        flash("La habitación ha sido modificada y tambien actualizada ")

        return redirect(url_for('rooms'))


# Esta es la ruta delete cuando se va eliminar  una habitacion
@app.route('/delete1/<id>/', methods=['GET', 'POST'])
def delete1(id):
    my_data = Data.query.get(id)
    db.session.delete(my_data)

    db.session.commit()
    flash("El registro de la habitación ha sido eliminado exitosamnete")

    return redirect(url_for('rooms'))

################################################################################################


def check_admin():
    # prevent non-admins from accessing the page
    if not current_user.is_admin:
        abort(403)

# Aqui se crea la tabla para todo nuestro proceso de CRUD de la base de datos


class Wk(db.Model):
    __tablename__ = 'weeks'
    id = db.Column(db.Integer, primary_key=True)
    start = db.Column(db.String(10))
    ends = db.Column(db.String(10))
    t1_tot = db.Column(db.Integer)
    t1_res = db.Column(db.Integer)
    t1_man = db.Column(db.Integer)
    t1_lib = db.Column(db.Integer)
    t2_tot = db.Column(db.Integer)
    t2_res = db.Column(db.Integer)
    t2_man = db.Column(db.Integer)
    t2_lib = db.Column(db.Integer)

    def __init__(self, start, ends, t1_tot, t1_res, t1_man, t1_lib, t2_tot, t2_res, t2_man, t2_lib):

        self.start = start
        self.ends = ends
        self.t1_tot = t1_tot
        self.t1_res = t1_res
        self.t1_man = t1_man
        self.t1_lib = t1_lib
        self.t2_tot = t2_tot
        self.t2_res = t2_res
        self.t2_man = t2_man
        self.t2_lib = t2_lib

# Esta es la ruta index del super administrador


@app.route('/super_admi2')
def super_admi2():
    return render_template("usuario_super.html")


# Esta es la ruta index donde vamos hacer las consultas de la base de datos

@app.route('/weeks', methods=['GET', 'POST'])
def weeks():
    # check_admin()
    all_data = Wk.query.all()

    return render_template("weeks/index2.html", xweeks=all_data)


# esta es la ruta insert para agregar  habitaciones usando formas en html
@app.route('/insert2', methods=['POST'])
def insert2():
    # check_admin()

    if request.method == 'POST':

        start = request.form['start']
        ends = request.form['ends']
        t1_tot = 25
        t1_res = int(request.form['t1_res'])
        t1_man = 0
        t1_lib = t1_tot - t1_res - t1_man
        t2_tot = 20
        t2_res = int(request.form['t2_res'])
        t2_man = 0
        t2_lib = t2_tot - t2_res - t2_man

        my_data = Wk(start, ends, t1_tot, t1_res, t1_man,
                     t1_lib, t2_tot, t2_res, t2_man, t2_lib)

        db.session.add(my_data)
        db.session.commit()

        flash("La semana ha sido agregada")

        return redirect(url_for('weeks'))


# Esta es la ruta update cuando se va a modificar una habitacion
@app.route('/update2', methods=['GET', 'POST'])
def update2():
    # check_admin()
    if request.method == 'POST':
        my_data = Wk.query.get(request.form.get('id'))

        my_data.start = request.form['start']
        # my_data.ends = request.form['ends']
        my_data.t1_res = int(request.form['t1_res'])
        my_data.t1_lib = my_data.t1_tot - \
            int(request.form['t1_res']) - my_data.t2_man
        my_data.t2_res = int(request.form['t2_res'])
        my_data.t2_lib = my_data.t2_tot - \
            int(request.form['t2_res']) - my_data.t2_man

        db.session.commit()
        flash("La informaciòn ha sido modificada y  actualizada ")

        return redirect(url_for('weeks'))


# Esta es la ruta delete cuando se va eliminar  una habitacion
@app.route('/delete2/<id>/', methods=['GET', 'POST'])
def delete2(id):
    # check_admin()
    my_data = Wk.query.get(id)
    db.session.delete2(my_data)

    db.session.commit()
    flash("El registro de la semana ha sido eliminado exitosamente")

    return redirect(url_for('weeks'))

################################################################################################


def check_admin():
    # prevent non-admins from accessing the page
    if not current_user.is_admin:
        abort(403)


@app.route('/admi3')
def admi3():

    return render_template("usuario_admin.html")


# Esta es la ruta index donde vamos hacer las consultas de la base de datos

@app.route('/mant', methods=['GET', 'POST'])
def mant():
    # check_admin()
    all_data = Wk.query.all()

    return render_template("mant/index3.html", xweeks=all_data)


# esta es la ruta insert para agregar  habitaciones usando formas en html
@app.route('/insert3', methods=['POST'])
def insert3():
    # check_admin()
    if request.method == 'POST':

        start = request.form['start']
        ends = request.form['ends']
        t1_tot = 25
        t1_res = int(request.form['t1_res'])
        t1_man = 0
        t1_lib = t1_tot - t1_res - t1_man
        t2_tot = 20
        t2_res = int(request.form['t2_res'])
        t2_man = 0
        t2_lib = t2_tot - t2_res - t2_man

        my_data = Wk(start, ends, t1_tot, t1_res, t1_man,
                     t1_lib, t2_tot, t2_res, t2_man, t2_lib)

        db.session.add(my_data)
        db.session.commit()

        flash("La semana ha sido agregada")

        return redirect(url_for('mant'))


# Esta es la ruta update cuando se va a modificar una habitacion
@app.route('/update3', methods=['GET', 'POST'])
def update3():
    # check_admin()
    if request.method == 'POST':
        my_data = Wk.query.get(request.form.get('id'))

        my_data.start = request.form['start']
        # my_data.ends = request.form['ends']
        my_data.t1_man = int(request.form['t1_man'])
        my_data.t1_lib = my_data.t1_tot - \
            int(request.form['t1_man']) - my_data.t2_res
        my_data.t2_man = int(request.form['t2_man'])
        my_data.t2_lib = my_data.t2_tot - \
            int(request.form['t2_man']) - my_data.t2_res

        db.session.commit()
        flash("La informaciòn ha sido modificada y  actualizada ")

        return redirect(url_for('mant'))


# Esta es la ruta delete cuando se va eliminar  una habitacion
@app.route('/delete3/<id>/', methods=['GET', 'POST'])
def delete(id):
    # check_admin()
    my_data = Wk.query.get(id)
    db.session.delete(my_data)

    db.session.commit()
    flash("El registro de la semana ha sido eliminado exitosamnete")

    return redirect(url_for('mant'))

################################################################################################


@app.route('/cliente1', methods=['GET', 'POST'])
def cliente1():
    # check_admin()
    return render_template("cliente/reservar.html")


@app.route('/cliente2', methods=['GET', 'POST'])
def cliente2():
    # check_admin()
    return render_template("cliente/condiciones.html")


@app.route('/cliente3', methods=['GET', 'POST'])
def cliente3():
    # check_admin()
    return render_template("cliente/bioseguridad.html")


######################################################################################################

@app.route('/get_db_connection', methods=['GET', 'POST'])
def get_db_connection():
    conn = sqlite3.connect('database/basehotel.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/get_post', methods=['GET', 'POST'])
def get_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?',
                        (post_id,)).fetchone()
    conn.close()

    if post is None:
        abort(404)
    return post


@app.route('/blog')
def blog():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return render_template('post/index4.html', posts=posts)


@app.route('/<int:post_id>')
def post(post_id):
    post = get_post(post_id)
    return render_template('post/post4.html', post=post)

# Crear un nuevo comentario sobre una habitación


@app.route('/create4', methods=('GET', 'POST'))
def create4():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title:
            flash('Ingrese un titulo del comentario!')
        else:
            conn = get_db_connection()
            conn.execute('INSERT INTO posts (title, content) VALUES (?, ?)',
                         (title, content))
            conn.commit()
            conn.close()
            return redirect(url_for('blog'))

    return render_template('post/create4.html')

# Editar y modificar  un nuevo comentario sobre una habitación


@app.route('/<int:id>/edit4', methods=('GET', 'POST'))
def edit4(id):
    post = get_post(id)

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title:
            flash('Ingrese un titulo del comentario!')
        else:
            conn = get_db_connection()
            conn.execute('UPDATE posts SET title = ?, content = ?'
                         ' WHERE id = ?',
                         (title, content, id))
            conn.commit()
            conn.close()
            return redirect(url_for('blog'))

    return render_template('post/edit4.html', post=post)

# Borrar y eliminar  un comentario sobre una habitación


@app.route('/<int:id>/delete4', methods=('POST',))
def delete4(id):
    post = get_post(id)
    conn = get_db_connection()
    conn.execute('DELETE FROM posts WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('"{}" El comentario fue eliminado correctamente!'.format(
        post['title']))
    return redirect(url_for('blog'))

###############################################################################################


if __name__ == "__main__":
    app.run(port=5000, debug=True)
