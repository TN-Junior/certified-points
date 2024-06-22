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
    app.run(debug=True)