from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
import os
from forms import UploadForm
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from wtforms import StringField, IntegerField, FileField, SubmitField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Optional
from functools import wraps
from flask_migrate import Migrate
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import pyscrypt

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')

# Configuração da conexão com o banco de dados MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configurar a timezone e o scheduler
timezone = pytz.timezone('America/Recife')
scheduler = BackgroundScheduler(timezone=timezone)

# Modelos de dados
class Curso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    pontos = db.Column(db.Integer, default=0)

class Certificado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qualificacao = db.Column(db.String(255), nullable=False)
    periodo = db.Column(db.String(50), nullable=True)
    carga_horaria = db.Column(db.Integer, nullable=False)
    quantidade = db.Column(db.Integer, nullable=True)
    pontos = db.Column(db.Integer, nullable=False)
    ano_conclusao = db.Column(db.Integer, nullable=True)
    ato_normativo = db.Column(db.String(100), nullable=True)
    tempo = db.Column(db.Integer, nullable=True)
    filename = db.Column(db.String(200), nullable=False)
    aprovado = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    curso_id = db.Column(db.Integer, db.ForeignKey('curso.id'))
    curso = db.relationship('Curso', backref=db.backref('certificados', lazy=True))

# Função para limpar certificados após 24 horas
def limpar_certificados():
    from datetime import datetime, timedelta
    limite = datetime.now() - timedelta(hours=24)
    certificados_para_deletar = Certificado.query.filter(Certificado.timestamp < limite).all()
    for certificado in certificados_para_deletar:
        db.session.delete(certificado)
    db.session.commit()
    print("Certificados antigos foram limpos.")

# Agendar a tarefa para rodar a cada 24 horas
def iniciar_scheduler():
    scheduler.add_job(limpar_certificados, 'interval', hours=24)
    scheduler.start()

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    matricula = db.Column(db.String(80), unique=True, nullable=False)
    nome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    pontuacao = db.Column(db.Integer, default=0)
    senha = db.Column(db.String(255), nullable=False)
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

# Definindo curso_para_qualificacao fora das funções para ser globalmente acessível
curso_para_qualificacao = {
    'Gov In Play': 'Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.',
    # Adicione mais cursos e suas qualificações correspondentes aqui
}

def calcular_pontos(certificado_data):
    qualificacao = certificado_data['qualificacao']
    horas = certificado_data['horas']
    pontos = 0

    qualificacao = curso_para_qualificacao.get(qualificacao, qualificacao)

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

def hash_password(password):
    salt = os.urandom(16)
    hashed = pyscrypt.hash(password=password.encode('utf-8'), salt=salt, N=2048, r=8, p=1, dkLen=32)
    return salt.hex() + ':' + hashed.hex()

def verify_password(stored_password, provided_password):
    try:
        salt, stored_hash = stored_password.split(':', 1)  # Limitando a divisão para no máximo 2 partes
        salt = bytes.fromhex(salt)
        provided_hash = pyscrypt.hash(password=provided_password.encode('utf-8'), salt=salt, N=2048, r=8, p=1, dkLen=32).hex()
        return stored_hash == provided_hash
    except ValueError as e:
        print(f"Erro ao verificar a senha: {e}")
        print(f"stored_password: {stored_password}")
        return False

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

    if usuario_db and verify_password(usuario_db.senha, senha):
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
            'periodo': form.periodo.data,
            'horas': form.horas.data,
            'quantidade': form.quantidade.data,
            'pontos': form.pontos.data,
            'ano_conclusao': form.ano_conclusao.data,
            'ato_normativo': form.ato_normativo.data,
            'tempo': form.tempo.data,
        }
        pontos = calcular_pontos(certificado_data)
        file = form.certificate.data
        filename = secure_filename(file.filename)

        # Verificar e criar o diretório de uploads, se necessário
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        file.save(os.path.join(upload_folder, filename))

        # Mapear a qualificação para garantir que "Gov In Play" seja substituído corretamente
        qualificacao_original = form.qualificacao.data
        qualificacao = curso_para_qualificacao.get(qualificacao_original, qualificacao_original)

        # Criar e salvar o novo certificado no banco de dados
        novo_certificado = Certificado(
            qualificacao=qualificacao_original,  # Exibir qualificação conforme preenchido
            periodo=form.periodo.data,
            carga_horaria=form.horas.data,
            quantidade=form.quantidade.data,
            pontos=pontos,
            ano_conclusao=form.ano_conclusao.data,
            ato_normativo=form.ato_normativo.data,
            tempo=form.tempo.data,
            filename=filename,
            curso_id=None
        )
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

@app.route('/delete/<int:certificado_id>', methods=['POST'])
@requires_admin
def delete_file(certificado_id):
    certificado = Certificado.query.get(certificado_id)
    if certificado:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], certificado.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(certificado)
        db.session.commit()
        flash(f'O certificado {certificado.filename} foi deletado com sucesso!')
    else:
        flash(f'O certificado {certificado_id} não foi encontrado.')
    return redirect(url_for('certificados'))

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

        # Gerar hash da senha usando pyscrypt
        hashed_senha = hash_password(senha)

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
            # Gerar hash da senha usando pyscrypt
            usuario.senha = hash_password(request.form['senha'])
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
    cursos_list = Curso.query.all()
    return render_template('cursos.html', cursos=cursos_list)

@app.route('/aprovar/<int:certificado_id>', methods=['POST'])
@requires_admin
def aprovar_certificado(certificado_id):
    certificado = Certificado.query.get(certificado_id)
    if certificado:
        certificado.aprovado = True
        curso_qualificacao = curso_para_qualificacao.get(certificado.qualificacao, certificado.qualificacao)
        
        # Atualiza ou cria o curso e adiciona os pontos corretamente
        curso = Curso.query.filter_by(nome=curso_qualificacao).first()
        if curso:
            curso.pontos += certificado.pontos
        else:
            curso = Curso(nome=curso_qualificacao, pontos=certificado.pontos)
            db.session.add(curso)
        db.session.commit()
        flash('Certificado aprovado e pontos adicionados ao curso!')
        return redirect(url_for('certificados'))
    else:
        flash('Certificado não encontrado.')
        return redirect(url_for('certificados'))

@app.route('/deletar_certificado/<int:certificado_id>', methods=['POST'])
@requires_admin
def deletar_certificado(certificado_id):
    certificado = Certificado.query.get(certificado_id)
    if certificado:
        db.session.delete(certificado)
        db.session.commit()
        flash('Certificado deletado com sucesso!')
    else:
        flash('Certificado não encontrado.')
    return redirect(url_for('certificados'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed inicial para garantir que os cursos estão no banco de dados
        cursos = [
            "Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.",
            "Cursos de atualização realizados, promovidos, articulados ou admitidos pelo Município do Recife.",
            "Cursos de aperfeiçoamento realizados, promovidos, articulados ou admitidos pelo Município do Recife.",
            "Cursos de graduação e especialização realizados em instituição pública ou privada, reconhecida pelo MEC.",
            "Mestrado, doutorado e pós-doutorado realizados em instituição pública ou privada, reconhecida pelo MEC.",
            "Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.",
            "Participação em grupos, equipes, comissões e projetos especiais, no âmbito do Município do Recife, formalizados por ato oficial.",
            "Exercício de cargos comissionados e funções gratificadas, ocupados, exclusivamente, no âmbito do Poder Executivo Municipal."
        ]

        for nome in cursos:
            if not Curso.query.filter_by(nome=nome).first():
                curso = Curso(nome=nome)
                db.session.add(curso)
        db.session.commit()
        
        iniciar_scheduler()
    app.run(host='0.0.0.0', port=5000, debug=True)
