from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
from urllib.parse import quote as url_quote
import os
from forms import UploadForm
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from wtforms import StringField, IntegerField, FileField, SubmitField, SelectField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Optional
from functools import wraps
from flask import abort
from wtforms.validators import DataRequired, Email
from flask_migrate import Migrate
from sqlalchemy import create_engine
# Importando as rotas
from routes import *

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')

# Configuração da conexão com o banco de dados MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

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
    role = db.Column(db.String(20), default='user')

    def __repr__(self):
        return f'<Usuario {self.nome}>'

class UploadForm(FlaskForm):
    qualificacao = StringField('Qualificação', validators=[DataRequired()])
    periodo = StringField('Período', validators=[Optional()])
    horas = IntegerField('Horas', validators=[DataRequired()])
    quantidade = IntegerField('Quantidade', validators=[Optional()])
    pontos = IntegerField('Pontos', validators=[Optional()])
    ano_conclusao = IntegerField('Ano de Conclusão', validators=[Optional()])
    ato_normativo = StringField('Ato Normativo', validators=[Optional()])
    tempo = IntegerField('Tempo (anos)', validators=[Optional()])
    certificate = FileField('Certificado', validators=[DataRequired()])
    submit = SubmitField('Enviar')

def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        usuario = Usuario.query.filter_by(matricula=session.get('usuario_logado')).first()
        if usuario and usuario.role == 'admin':
            return f(*args, **kwargs)
        else:
            flash('Acesso negado. Área restrita a administradores.')
            return redirect(url_for('index'))
    return decorated_function

def calcular_pontos(certificado_data):
    qualificacao = certificado_data['qualificacao']
    horas = certificado_data['horas']
    pontos = 0
    
    if qualificacao == 'Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
        pontos = (horas // 20) * 2
    elif qualificacao == 'Cursos de atualização realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
        if horas >= 40:
            pontos = 5
    elif qualificacao == 'Cursos de aperfeiçoamento realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
        if horas >= 180:
            pontos = 10
    elif qualificacao == 'Cursos de graduação e especialização realizados em instituição pública ou privada, reconhecida pelo MEC.':
        if horas >= 360:
            pontos = 20
    elif qualificacao == 'Mestrado, doutorado e pós-doutorado realizados em instituição pública ou privada, reconhecida pelo MEC.':
        pontos = 30
    elif qualificacao == 'Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.':
        pontos = (horas // 8) * 2
        if pontos > 10:
            pontos = 10
    elif qualificacao == 'Participação em grupos, equipes, comissões e projetos especiais, no âmbito do Município do Recife, formalizados por ato oficial.':
        pontos = 5
        if pontos > 10:
            pontos = 10
    elif qualificacao == 'Exercício de cargos comissionados e funções gratificadas, ocupados, exclusivamente, no âmbito do Poder Executivo Municipal.':
        pontos = (horas // 12) * 10  # Assumindo que 'tempo' foi fornecido em meses, 12 meses = 1 ano
        if pontos > 15:
            pontos = 15
    
    return pontos

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
        flash(f'{usuario} logado com sucesso!')
        # Verifica o role do usuário e redireciona conforme necessário
        if usuario_db.role == 'admin':
            return redirect(url_for('certificados'))  # Redireciona o admin para a tela de certificados
        else:
            return redirect(url_for('upload'))  # Redireciona usuários não-admin para outra rota relevante
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
        certificado_data = {
            'qualificacao': form.qualificacao.data,
            'horas': form.horas.data,
        }
        pontos = calcular_pontos(certificado_data)
        file = form.certificate.data
        filename = secure_filename(file.filename)

        # Verificar e criar o diretório de uploads, se necessário
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        file.save(os.path.join(upload_folder, filename))

        # Criar e salvar o novo certificado no banco de dados
        novo_certificado = Certificado(curso=form.qualificacao.data, carga_horaria=form.horas.data, pontos=pontos, filename=filename)
        db.session.add(novo_certificado)
        db.session.commit()

        flash('Certificado enviado com sucesso!')
        return redirect(url_for('certificados'))
    return render_template('upload.html', form=form)

@app.route('/certificados')
@requires_admin
def certificados():
    certificados = Certificado.query.all()
    return render_template('certificados.html', certificados=certificados)

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
    try:
        matricula = request.form['matricula']
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        role = request.form['role']
        hashed_senha = generate_password_hash(senha, method='scrypt')

        novo_usuario = Usuario(matricula=matricula, nome=nome, email=email, senha=hashed_senha, role=role)
        db.session.add(novo_usuario)
        db.session.commit()
        flash(f'Usuário {nome} cadastrado com sucesso!')
        return redirect('/login')
    except Exception as e:
        print(e)
        db.session.rollback()
        flash(f'Erro ao cadastrar usuário: {str(e)}')
        return redirect('/signup')

# Lista todos os usuários (Read)
@app.route('/usuarios')
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

# Atualiza um usuário (Update)
@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    usuario = Usuario.query.get(id)
    if request.method == 'POST':
        usuario.matricula = request.form['matricula']
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        if request.form['senha']:
            usuario.senha = generate_password_hash(request.form['senha'], method='scrypt')
        try:
            db.session.commit()
            flash('Usuário atualizado com sucesso!')
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar usuário: {str(e)}')
    return render_template('editar_usuario.html', usuario=usuario)

# Deleta um usuário (Delete)
@app.route('/deletar_usuario/<int:id>', methods=['POST'])
def deletar_usuario(id):
    usuario = Usuario.query.get(id)
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário deletado com sucesso!')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao deletar usuário: {str(e)}')
    return redirect(url_for('listar_usuarios'))

@app.route('/cursos')
def cursos():
    cursos_list = [
        {"nome": "Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.", "pontos": 10},
        {"nome": "Cursos de atualização realizados, promovidos, articulados ou admitidos pelo Município do Recife.", "pontos": 8},
        {"nome": "Cursos de aperfeiçoamento realizados, promovidos, articulados ou admitidos pelo Município do Recife.", "pontos": 7},
        {"nome": "Cursos de graduação e especialização realizados em instituição pública ou privada, reconhecida pelo MEC.", "pontos": 12},
        {"nome": "Mestrado, doutorado e pós-doutorado realizados em instituição pública ou privada, reconhecida pelo MEC.", "pontos": 15},
        {"nome": "Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.", "pontos": 5},
        {"nome": "Participação em grupos, equipes, comissões e projetos especiais, no âmbito do Município do Recife, formalizados por ato oficial.", "pontos": 4},
        {"nome": "Exercício de cargos comissionados e funções gratificadas, ocupados, exclusivamente, no âmbito do Poder Executivo Municipal.", "pontos": 3}
    ]
    return render_template('cursos.html', cursos=cursos_list)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
