from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
from urllib.parse import quote as url_quote
import os
from forms import UploadForm
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')

# Configuração da conexão com o banco de dados MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Modelos de dados
class Certificado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    curso = db.Column(db.String(100), nullable=False)
    carga_horaria = db.Column(db.Integer, nullable=False)
    pontos = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(200), nullable=False)

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    matricula = db.Column(db.String(80), unique=True, nullable=False)
    nome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    pontuacao = db.Column(db.Integer, default=0)
    senha = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<Usuario {self.nome}>'

    def __repr__(self):
        return f'<Usuario {self.usuario}>'

'''def calcular_pontos(certificado):
    pontos = 0
    nome = certificado['nome']
    horas = certificado['horas']

    if 'seminários' in nome or 'congressos' in nome or 'oficinas' in nome:
        pontos = (horas // 20) * 2
    elif 'atualização' in nome:
        if horas >= 40:
            pontos = 5
    elif 'aperfeiçoamento' in nome:
        if horas >= 180:
            pontos = 10
    elif 'graduação' in nome or 'especialização' in nome:
        if horas == 360:
            pontos = 20
    elif 'Mestrado' in nome or 'Doutorado' in nome or 'Pós-doutorado' in nome:
        pontos = 30
    elif 'Instrutoria' in nome or 'Coordenação' in nome:
        pontos = (horas // 8) * 2
        if pontos > 10:
            pontos = 10
    elif 'grupos' in nome or 'equipes' in nome or 'comissões' in nome or 'projetos especiais' in nome:
        pontos = 5
        if pontos > 10:
            pontos = 10
    elif 'cargos comissionados' in nome or 'funções gratificadas' in nome:
        pontos = (horas // 12) * 10  # assumindo que 'horas' está em meses
        if pontos > 15:
            pontos = 15

    return pontos'''


@app.route('/')
def index():
    return render_template('home.html', titulo='Bem-vindo ao Certification')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/autenticar', methods=['POST'])
def autenticar():
    usuario = request.form['usuario']
    senha = request.form['senha']
    usuario_db = Usuario.query.filter_by(matricula=usuario).first()

    if usuario_db and check_password_hash(usuario_db.senha, senha):
        session['usuario_logado'] = usuario
        flash(usuario + ' logado com sucesso!')
        return redirect('/upload')
    else:
        flash('Usuário ou senha inválidos.')
        return redirect('/login')

@app.route('/logout')
def logout():
    session['usuario_logado'] = None
    flash('Logout efetuado com sucesso!')
    return redirect('/')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        curso = form.curso.data
        carga_horaria = form.carga_horaria.data
        pontos = calcular_pontos({'nome': curso, 'horas': carga_horaria})
        file = form.certificate.data
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        session['certificado'] = {
            'curso': curso,
            'carga_horaria': carga_horaria,
            'pontos': pontos,
            'filename': filename
        }
        flash('Certificado enviado com sucesso!')
        return redirect(url_for('certificados'))
    return render_template('upload.html', form=form)

@app.route('/certificados')
def certificados():
    certificado = session.get('certificado')
    if not certificado:
        flash('Nenhum certificado enviado.')
        return redirect(url_for('upload'))
    return render_template('certificados.html', certificado=certificado)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'O arquivo {filename} foi deletado com sucesso!')
    else:
        flash(f'O arquivo {filename} não foi encontrado.')
    return redirect(url_for('upload'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/cadastrar', methods=['POST'])
def cadastrar():
    matricula = request.form['matricula']
    nome = request.form['nome']
    email = request.form['email']
    senha = request.form['senha']
    hashed_senha = generate_password_hash(senha, method='scrypt')

    novo_usuario = Usuario(matricula=matricula, nome=nome, email=email, senha=hashed_senha)

    try:
        db.session.add(novo_usuario)
        db.session.commit()
        flash(f'Usuário {nome} cadastrado com sucesso!')
        return redirect('/login')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao cadastrar usuário: {str(e)}')
        return redirect('/signup')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)