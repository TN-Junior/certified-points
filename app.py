from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory, jsonify
from werkzeug.utils import secure_filename
import os
from forms import UploadForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv
from wtforms import StringField, IntegerField, FileField, SubmitField, SelectField, DateField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Optional
from functools import wraps
from flask_migrate import Migrate
from sqlalchemy import create_engine
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import pyscrypt
from datetime import datetime

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

# Configuração para tornar a sessão não permanente, ou seja, expira quando o navegador é fechado "Desloga ao fechar guia ou navegador"
app.config['SESSION_PERMANENT'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configurar a timezone e o scheduler
timezone = pytz.timezone('America/Recife')
scheduler = BackgroundScheduler(timezone=timezone)

# Lista de qualificações
QUALIFICACOES = [
    "Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.",
    "Cursos de atualização realizados, promovidos, articulados ou admitidos pelo Município do Recife.",
    "Cursos de aperfeiçoamento realizados, promovidos, articulados ou admitidos pelo Município do Recife.",
    "Cursos de graduação e especialização realizados em instituição pública ou privada, reconhecida pelo MEC.",
    "Mestrado, doutorado e pós-doutorado realizados em instituição pública ou privada, reconhecida pelo MEC.",
    "Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.",
    "Participação em grupos, equipes, comissões e projetos especiais, no âmbito do Município do Recife, formalizados por ato oficial.",
    "Exercício de cargos comissionados e funções gratificadas, ocupados, exclusivamente, no âmbito do Poder Executivo Municipal."
]

# Modelos de dados
class Curso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    pontos = db.Column(db.Integer, default=0)

class Certificado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    protocolo = db.Column(db.String(50), unique=True, nullable=False)
    qualificacao = db.Column(db.String(255), nullable=False)
    periodo = db.Column(db.Date, nullable=True)
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
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    usuario = db.relationship('Usuario', backref=db.backref('certificados', lazy=True))

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

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    recipient = db.Column(db.String(150), nullable=False)  # Pode ser 'admin' para todos os admins

class UploadForm(FlaskForm):
    qualificacao = SelectField(
        'Qualificação',
        choices=[
            ('', 'Selecione'),
            *[(qualificacao, qualificacao) for qualificacao in QUALIFICACOES]
        ],
        validators=[DataRequired(message="Selecione uma qualificação.")]
    )
    periodo = DateField('Período', validators=[Optional()])
    horas = IntegerField('Horas', validators=[DataRequired()])
    quantidade = IntegerField('Quantidade', validators=[Optional()])
    ano_conclusao = IntegerField('Ano de Conclusão', validators=[Optional()])
    ato_normativo = StringField('Ato Normativo', validators=[Optional()])
    tempo = IntegerField('Tempo (anos/meses)', validators=[Optional()])
    certificate = FileField('Certificado', validators=[DataRequired()])
    submit = SubmitField('Enviar')

def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        usuario_id = session.get('usuario_logado')
        usuario = db.session.get(Usuario, usuario_id)
        if usuario and usuario.role == 'admin':
            return f(*args, **kwargs)
        else:
            flash('Acesso negado. Área restrita a administradores.')
            return redirect(url_for('index'))
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_logado' not in session:
            flash('Você precisa estar logado para acessar essa página.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def calcular_pontos(certificado_data):
    qualificacao = certificado_data['qualificacao']
    horas = certificado_data['horas']
    tempo = certificado_data.get('tempo', 0)
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
        pontos = (tempo // 6) * 10
        if pontos > 15:
            pontos = 15

    return pontos

def hash_password(password):
    salt = os.urandom(16)
    hashed = pyscrypt.hash(password=password.encode('utf-8'), salt=salt, N=2048, r=8, p=1, dkLen=32)
    return salt.hex() + ':' + hashed.hex()

def verify_password(stored_password, provided_password):
    try:
        salt, stored_hash = stored_password.split(':', 1)
        salt = bytes.fromhex(salt)
        provided_hash = pyscrypt.hash(password=provided_password.encode('utf-8'), salt=salt, N=2048, r=8, p=1, dkLen=32).hex()
        return stored_hash == provided_hash
    except ValueError as e:
        print(f"Erro ao verificar a senha: {e}")
        print(f"stored_password: {stored_password}")
        return False

def generate_protocol(usuario_id):
    current_year = datetime.now().year
    last_certificate = Certificado.query.filter(
        Certificado.usuario_id == usuario_id,
        Certificado.protocolo.like(f"{current_year}-%")
    ).order_by(Certificado.id.desc()).first()

    if last_certificate:
        last_protocol = last_certificate.protocolo
        last_number = int(last_protocol.split('-')[-1])
        new_number = last_number + 1
    else:
        new_number = 1

    new_protocol = f"{current_year}-{new_number:04d}"
    return new_protocol

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
        session['usuario_logado'] = usuario_db.id
        session['usuario_role'] = usuario_db.role

        flash(f'{usuario_db.nome} logado com sucesso!')
        if usuario_db.role == 'admin':
            return redirect(url_for('certificados'))
        else:
            return redirect(url_for('upload'))
    else:
        flash('Usuário ou senha inválidos.')
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('usuario_logado', None)
    session.pop('usuario_role', None)
    flash('Logout efetuado com sucesso!')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        usuario_id = session.get('usuario_logado')
        certificado_data = {
            'qualificacao': form.qualificacao.data,
            'periodo': form.periodo.data,
            'horas': form.horas.data,
            'quantidade': form.quantidade.data,
            'ano_conclusao': form.ano_conclusao.data,
            'ato_normativo': form.ato_normativo.data,
            'tempo': form.tempo.data,
        }
        pontos = calcular_pontos(certificado_data)
        file = form.certificate.data
        filename = secure_filename(file.filename)

        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        file.save(os.path.join(upload_folder, filename))

        protocolo = generate_protocol(usuario_id)

        novo_certificado = Certificado(
            protocolo=protocolo,
            qualificacao=form.qualificacao.data,  
            periodo=form.periodo.data,
            carga_horaria=form.horas.data,
            quantidade=form.quantidade.data,
            pontos=pontos,
            ano_conclusao=form.ano_conclusao.data,
            ato_normativo=form.ato_normativo.data,
            tempo=form.tempo.data,
            filename=filename,
            usuario_id=usuario_id
        )
        db.session.add(novo_certificado)
        db.session.commit()

        flash('Certificado enviado com sucesso!')
        return redirect(url_for('upload'))
    return render_template('upload.html', form=form)

@app.route('/certificados')
@requires_admin
def certificados():
    certificados = Certificado.query.all()
    # Converter strings de data para objetos Date
    for certificado in certificados:
        if isinstance(certificado.periodo, str):
            certificado.periodo = datetime.strptime(certificado.periodo, '%Y-%m-%d').date()
    return render_template('certificados.html', certificados=certificados)

@app.route('/certificados_pendentes')
@login_required
def certificados_pendentes():
    usuario_id = session.get('usuario_logado')
    certificados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=False).all()
    # Converter strings de data para objetos Date
    for certificado in certificados:
        if isinstance(certificado.periodo, str):
            certificado.periodo = datetime.strptime(certificado.periodo, '%Y-%m-%d').date()
    return render_template('certificados_pendentes.html', certificados=certificados)


@app.route('/certificados_aprovados')
@login_required
def certificados_aprovados():
    usuario_id = session.get('usuario_logado')
    certificados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=True).all()
    # Converter strings de data para objetos Date
    for certificado in certificados:
        if isinstance(certificado.periodo, str):
            certificado.periodo = datetime.strptime(certificado.periodo, '%Y-%m-%d').date()
    return render_template('certificados_aprovados.html', certificados=certificados)

@app.route('/painel')
@login_required
def painel():
    usuario_id = session.get('usuario_logado')
    usuario = db.session.get(Usuario, usuario_id)
    if usuario.role == 'admin':
        return redirect(url_for('certificados'))
    else:
        return render_template('painel.html', usuario=usuario)

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
@requires_admin
def signup():
    return render_template('signup.html')

@app.route('/cadastrar', methods=['POST'])
@requires_admin
def cadastrar():
    try:
        matricula = request.form['matricula']
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        role = request.form['role']

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
@requires_admin
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

# Atualiza um usuário (Update)
@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@requires_admin
def editar_usuario(id):
    usuario = db.session.get(Usuario, id)
    if request.method == 'POST':
        usuario.matricula = request.form['matricula']
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        if request.form['senha']:
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
@requires_admin
def deletar_usuario(id):
    usuario = db.session.get(Usuario, id)
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário deletado com sucesso!')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao deletar usuário: {str(e)}')
    return redirect(url_for('listar_usuarios'))

@app.route('/cursos')
@login_required
def cursos():
    usuario_id = session.get('usuario_logado')
    usuario = db.session.get(Usuario, usuario_id)

    # Filtrar certificados aprovados do usuário logado
    certificados_aprovados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=True).all()

    # Inicializar o dicionário de pontos para cada qualificação
    cursos_pontos = {qualificacao: 0 for qualificacao in QUALIFICACOES}

    # Somar os pontos dos certificados aprovados do usuário logado
    for certificado in certificados_aprovados:
        cursos_pontos[certificado.qualificacao] += certificado.pontos

    cursos_list = [{'nome': nome, 'pontos': pontos} for nome, pontos in cursos_pontos.items()]

    return render_template('cursos.html', cursos=cursos_list, usuario=usuario)

@app.route('/aprovar/<int:certificado_id>', methods=['POST'])
@requires_admin
def aprovar_certificado(certificado_id):
    certificado = db.session.get(Certificado, certificado_id)
    if certificado:
        certificado.aprovado = True

        # Adicionar pontos ao usuário específico que submeteu o certificado
        usuario = db.session.get(Usuario, certificado.usuario_id)
        if usuario:
            usuario.pontuacao += certificado.pontos

        db.session.commit()
        flash('Certificado aprovado e pontos adicionados ao usuário!')
        return redirect(url_for('certificados'))
    else:
        flash('Certificado não encontrado ou você não tem permissão para aprová-lo.')
        return redirect(url_for('certificados'))

@app.route('/deletar_certificado/<int:certificado_id>', methods=['POST'])
@requires_admin
def deletar_certificado(certificado_id):
    certificado = db.session.get(Certificado, certificado_id)
    if certificado:
        db.session.delete(certificado)
        db.session.commit()
        flash('Certificado deletado com sucesso!')
    else:
        flash('Certificado não encontrado.')
    return redirect(url_for('certificados'))


@app.route('/api/mensagens_usuario', methods=['POST'])
@login_required
def api_post_mensagens_usuario():
    data = request.get_json()
    mensagem_content = data.get('mensagem')
    sender = session.get('usuario_logado')
    recipient = 'admin'  # Todas as mensagens são enviadas para os administradores

    if not mensagem_content:
        return jsonify({'error': 'Mensagem não pode ser vazia'}), 400

    nova_mensagem = Message(content=mensagem_content, sender=sender, recipient=recipient)
    db.session.add(nova_mensagem)
    db.session.commit()

    return jsonify({'success': 'Mensagem enviada com sucesso'})


@app.route('/api/mensagens', methods=['GET'])
def api_get_mensagens():
    if not session.get('usuario_logado') or session.get('usuario_role') != 'admin':
        return jsonify({'error': 'Acesso negado'}), 403

    mensagens = Message.query.filter_by(recipient='admin').order_by(Message.timestamp.desc()).all()
    mensagens_json = [{'sender': m.sender, 'content': m.content, 'timestamp': m.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for m in mensagens]
    return jsonify(mensagens_json)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed inicial para garantir que os cursos estão no banco de dados
        for nome in QUALIFICACOES:
            if not Curso.query.filter_by(nome=nome).first():
                curso = Curso(nome=nome)
                db.session.add(curso)
        db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=True)
