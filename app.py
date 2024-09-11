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
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import pyscrypt
from datetime import datetime

# Carregar variáveis de ambiente
load_dotenv()

# Configuração do aplicativo Flask
app = Flask(__name__)
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
app.config['SESSION_PERMANENT'] = False

# Inicialização do SQLAlchemy e migrações
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configuração de fuso horário e agendador
timezone = pytz.timezone('America/Recife')
scheduler = BackgroundScheduler(timezone=timezone)

# Constantes
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

# Modelos
class Curso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    pontos = db.Column(db.Integer, default=0)

class Certificado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    protocolo = db.Column(db.String(50), unique=True, nullable=False)
    qualificacao = db.Column(db.String(255), nullable=False)
    periodo_de = db.Column(db.Date, nullable=True)
    periodo_ate = db.Column(db.Date, nullable=True)
    carga_horaria = db.Column(db.Integer, nullable=True)
    quantidade = db.Column(db.Integer, nullable=True)
    pontos = db.Column(db.Integer, nullable=False)
    horas_excedentes = db.Column(db.Integer, nullable=False, default=0)
    ano_conclusao = db.Column(db.Integer, nullable=True)
    ato_normativo = db.Column(db.String(100), nullable=True)
    tempo = db.Column(db.Integer, nullable=True)
    filename = db.Column(db.String(200), nullable=False)
    aprovado = db.Column(db.Boolean, default=False)
    recusado = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    curso_id = db.Column(db.Integer, db.ForeignKey('curso.id'))
    curso = db.relationship('Curso', backref=db.backref('certificados', lazy=True))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    usuario = db.relationship('Usuario', backref=db.backref('certificados', lazy=True))
    progressao = db.Column(db.Integer, default=0)

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
    recipient = db.Column(db.String(150), nullable=False)

# Formulários
class UploadForm(FlaskForm):
    qualificacao = SelectField(
        'Qualificação',
        choices=[('', 'Selecione')] + [(qualificacao, qualificacao) for qualificacao in QUALIFICACOES],
        validators=[DataRequired(message="Selecione uma qualificação.")]
    )
    periodo_de = DateField('Período (de)', validators=[Optional()])
    periodo_ate = DateField('Período (até)', validators=[Optional()])
    horas = IntegerField('Horas', validators=[Optional()])
    quantidade = IntegerField('Quantidade', validators=[Optional()])
    ano_conclusao = IntegerField('Ano de Conclusão', validators=[Optional()])
    ato_normativo = StringField('Ato Normativo', validators=[Optional()])
    tempo = IntegerField('Tempo (anos/meses)', validators=[Optional()])
    certificate = FileField('Certificado', validators=[DataRequired(message="Certificado é obrigatório.")])
    submit = SubmitField('Enviar')

    def validate(self, **kwargs):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        qualificacoes_com_horas = [
            'Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.',
            'Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.',
            'Cursos de atualização realizados, promovidos, articulados ou admitidos pelo Município do Recife.',
            'Cursos de aperfeiçoamento realizados, promovidos, articulados ou admitidos pelo Município do Recife.'
        ]

        if self.qualificacao.data in qualificacoes_com_horas and not self.horas.data:
            self.horas.errors.append("Este campo é obrigatório para a qualificação selecionada.")
            return False

        return True


# Funções utilitárias
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

def parse_date(date_string):
    try:
        return datetime.strptime(date_string, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None

def calcular_pontos(certificado_data):
    qualificacao = certificado_data['qualificacao']
    horas = certificado_data.get('horas', 0)  # Define 0 se horas for None
    tempo = certificado_data.get('tempo', 0)
    pontos = 0
    horas_excedentes = 0

    if qualificacao == 'Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
        pontos = (horas // 20) * 2
        horas_excedentes = horas % 20
    elif qualificacao == 'Cursos de atualização realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
        if horas is not None and horas >= 40:
            pontos = 5
            horas_excedentes = horas - 40
    elif qualificacao == 'Cursos de aperfeiçoamento realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
        if horas is not None and horas >= 180:
            pontos = 10
            horas_excedentes = horas - 180
    elif qualificacao == 'Cursos de graduação e especialização realizados em instituição pública ou privada, reconhecida pelo MEC.':
        if horas is not None and horas >= 360:
            pontos = 20
            horas_excedentes = horas - 360
    elif qualificacao == 'Mestrado, doutorado e pós-doutorado realizados em instituição pública ou privada, reconhecida pelo MEC.':
        pontos = 30
        horas_excedentes = 0
    elif qualificacao == 'Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.':
        if horas is not None:
            pontos = (horas // 8) * 2
            if pontos > 10:
                pontos = 10
            horas_excedentes = horas % 8
    elif qualificacao == 'Participação em grupos, equipes, comissões e projetos especiais, no âmbito do Município do Recife, formalizados por ato oficial.':
        pontos = 5
        if pontos > 10:
            pontos = 10
    elif qualificacao == 'Exercício de cargos comissionados e funções gratificadas, ocupados, exclusivamente, no âmbito do Poder Executivo Municipal.':
        if tempo is not None:
            pontos = (tempo // 6) * 10
            if pontos > 15:
                pontos = 15
        horas_excedentes = 0

    return pontos, horas_excedentes

def calcular_pontos_cursos_aprovados(usuario_id):
    """
    Calcula os pontos e horas excedentes dos cursos aprovados de um usuário.
    """
    certificados_aprovados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=True).all()
    cursos_excedentes = {qualificacao: {'pontos': 0, 'horas_excedentes': 0} for qualificacao in QUALIFICACOES}

    for certificado in certificados_aprovados:
        cursos_excedentes[certificado.qualificacao]['pontos'] += certificado.pontos
        cursos_excedentes[certificado.qualificacao]['horas_excedentes'] += certificado.horas_excedentes

        if certificado.qualificacao == 'Cursos, seminários, congressos e oficinas realizados, promovidos, articulados ou admitidos pelo Município do Recife.':
            extra_pontos = (cursos_excedentes[certificado.qualificacao]['horas_excedentes'] // 20) * 2
            cursos_excedentes[certificado.qualificacao]['pontos'] += extra_pontos
            cursos_excedentes[certificado.qualificacao]['horas_excedentes'] %= 20

        elif certificado.qualificacao == 'Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.':
            max_pontos = 10
            pontos_instrutoria = (cursos_excedentes[certificado.qualificacao]['horas_excedentes'] // 8) * 2
            if cursos_excedentes[certificado.qualificacao]['pontos'] + pontos_instrutoria > max_pontos:
                pontos_instrutoria = max_pontos - cursos_excedentes[certificado.qualificacao]['pontos']
            cursos_excedentes[certificado.qualificacao]['pontos'] += pontos_instrutoria
            cursos_excedentes[certificado.qualificacao]['horas_excedentes'] %= 8

    return cursos_excedentes

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

# Rotas
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
        return redirect(url_for('certificados') if usuario_db.role == 'admin' else url_for('upload'))
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
        periodo_de = form.periodo_de.data
        periodo_ate = form.periodo_ate.data

        certificado_data = {
            'qualificacao': form.qualificacao.data,
            'horas': form.horas.data,
            'quantidade': form.quantidade.data,
            'ano_conclusao': form.ano_conclusao.data,
            'ato_normativo': form.ato_normativo.data,
            'tempo': form.tempo.data,
        }
        pontos, horas_excedentes = calcular_pontos(certificado_data)
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
            periodo_de=periodo_de,
            periodo_ate=periodo_ate,
            carga_horaria=form.horas.data,
            quantidade=form.quantidade.data,
            pontos=pontos,
            horas_excedentes=horas_excedentes,
            ano_conclusao=form.ano_conclusao.data,
            ato_normativo=form.ato_normativo.data,
            tempo=form.tempo.data,
            filename=filename,
            usuario_id=usuario_id
        )
        db.session.add(novo_certificado)
        db.session.commit()

        flash('Certificado enviado com sucesso! Aguardando aprovação.')
        return redirect(url_for('certificados'))
    return render_template('upload.html', form=form)

@app.route('/certificados')
@login_required
@requires_admin
def certificados():
    certificado_index = request.args.get('index', 0, type=int)
    total_certificados = Certificado.query.filter_by(aprovado=False, recusado=False).count()
    certificados = Certificado.query.filter_by(aprovado=False, recusado=False).all()

    certificado_atual = certificados[certificado_index] if certificados else None
    next_index = certificado_index + 1 if certificado_index < total_certificados - 1 else None
    prev_index = certificado_index - 1 if certificado_index > 0 else None

    return render_template(
        'certificados.html',
        certificado_atual=certificado_atual,
        certificados=certificados,
        next_index=next_index,
        prev_index=prev_index
    )

@app.route('/certificados_pendentes')
@login_required
def certificados_pendentes():
    usuario_id = session.get('usuario_logado')
    certificados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=False).all()
    return render_template('certificados_pendentes.html', certificados=certificados)

@app.route('/certificados_aprovados')
@login_required
def certificados_aprovados():
    usuario_id = session.get('usuario_logado')
    certificados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=True).all()
    return render_template('certificados_aprovados.html', certificados=certificados)

@app.route('/painel')
@login_required
def painel():
    usuario_id = session.get('usuario_logado')
    usuario = db.session.get(Usuario, usuario_id)
    return redirect(url_for('certificados') if usuario.role == 'admin' else url_for('upload'))

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

@app.route('/usuarios')
@requires_admin
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

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
    cursos_excedentes = calcular_pontos_cursos_aprovados(usuario_id)

    cursos_list = [
        {
            'nome': nome,
            'pontos': data['pontos'],
            'horas_excedentes': data['horas_excedentes']
        } for nome, data in cursos_excedentes.items()
    ]

    return render_template('cursos.html', cursos=cursos_list)

@app.route('/aprovar/<int:certificado_id>', methods=['POST'])
@requires_admin
def aprovar_certificado(certificado_id):
    certificado = db.session.get(Certificado, certificado_id)
    if certificado:
        if not certificado.aprovado:
            certificado.aprovado = True
            usuario = db.session.get(Usuario, certificado.usuario_id)
            if usuario:
                usuario.pontuacao = (usuario.pontuacao or 0) + (certificado.pontos or 0)
                db.session.add(usuario)
            try:
                db.session.commit()
                flash('Certificado aprovado e pontos adicionados ao usuário!')
            except Exception as e:
                db.session.rollback()
                flash(f'Ocorreu um erro ao tentar aprovar o certificado: {str(e)}')
        else:
            flash('Este certificado já foi aprovado anteriormente e os pontos já foram adicionados.')
    else:
        flash('Certificado não encontrado ou você não tem permissão para aprová-lo.')
    return redirect(url_for('certificados'))

@app.route('/recusar_certificado/<int:certificado_id>', methods=['POST'])
@requires_admin
def recusar_certificado(certificado_id):
    certificado = db.session.get(Certificado, certificado_id)
    if certificado:
        certificado.aprovado = False
        certificado.recusado = True
        db.session.commit()
        flash('Certificado recusado com sucesso!')
    else:
        flash('Certificado não encontrado.')
    return redirect(url_for('certificados'))

@app.route('/api/mensagens_usuario', methods=['POST'])
@login_required
def api_post_mensagens_usuario():
    data = request.get_json()
    mensagem_content = data.get('mensagem')
    sender = session.get('usuario_logado')
    recipient = 'admin'

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

@app.route('/progressoes', methods=['GET', 'POST'])
@login_required
def progressoes():
    usuarios = Usuario.query.filter(Usuario.role != 'admin').all()
    usuario_id = request.form.get('usuario')

    if usuario_id:
        usuario_id = int(usuario_id)
    else:
        usuario_id = session.get('usuario_logado')

    # Calcula os pontos e horas excedentes dos cursos aprovados do usuário
    certificados_aprovados = Certificado.query.filter_by(usuario_id=usuario_id, aprovado=True).all()
    progressoes = {qualificacao: {'pontos': 0, 'progressao': 0, 'horas_excedentes': 0} for qualificacao in QUALIFICACOES}

    # Preenche os pontos e progressões atuais das qualificações
    for certificado in certificados_aprovados:
        progressoes[certificado.qualificacao]['pontos'] += certificado.pontos
        progressoes[certificado.qualificacao]['progressao'] += certificado.progressao
        progressoes[certificado.qualificacao]['horas_excedentes'] += certificado.horas_excedentes

    errors = {}

    limites_por_qualificacao = {
        'Instrutoria ou Coordenação de cursos promovidos pelo Município do Recife.': 10,
        'Participação em grupos, equipes, comissões e projetos especiais, no âmbito do Município do Recife, formalizados por ato oficial.': 10,
        'Exercício de cargos comissionados e funções gratificadas, ocupados, exclusivamente, no âmbito do Poder Executivo Municipal.': 15
    }

    if request.method == 'POST':
        # Itera sobre cada qualificação para aplicar progressões
        for i, (qualificacao, dados) in enumerate(progressoes.items()):
            progressao_key = f'progressao_{i + 1}'
            adicionar_key = f'adicionar_{i + 1}'
            botao_adicionar_key = f'botao_adicionar_{i + 1}'

            # Captura a quantidade de pontos que o usuário quer adicionar
            if botao_adicionar_key in request.form:
                progressao_valor = request.form.get(adicionar_key, '0')

                try:
                    progressao_valor = int(progressao_valor)
                except ValueError:
                    progressao_valor = 0

                if progressao_valor > dados['pontos']:
                    progressoes[qualificacao]['erro'] = True
                    errors[progressao_key] = "O valor inserido excede o saldo de pontos disponíveis."
                elif qualificacao in limites_por_qualificacao:
                    total_progressao = dados['progressao'] + progressao_valor
                    if total_progressao > limites_por_qualificacao[qualificacao]:
                        progressoes[qualificacao]['erro'] = True
                        errors[progressao_key] = f"O valor inserido excede o limite máximo de {limites_por_qualificacao[qualificacao]} pontos para esta qualificação."
                else:
                    # Aplica a quantidade correta de pontos conforme especificado pelo usuário
                    if progressao_valor <= dados['pontos']:
                        certificados_aprovados_qualificacao = Certificado.query.filter_by(
                            usuario_id=usuario_id,
                            aprovado=True,
                            qualificacao=qualificacao
                        ).all()

                        # Distribui o valor inserido entre os certificados e atualiza a progressão
                        for certificado in certificados_aprovados_qualificacao:
                            if progressao_valor > 0 and certificado.pontos > 0:
                                restante = min(progressao_valor, certificado.pontos)
                                certificado.progressao += restante
                                certificado.pontos -= restante
                                progressoes[qualificacao]['pontos'] -= restante
                                progressoes[qualificacao]['progressao'] += restante
                                progressao_valor -= restante
                                db.session.add(certificado)  # Atualiza o certificado no banco de dados

                        # Salva imediatamente após clicar em "Adicionar"
                        db.session.commit()
                        flash("Pontos de progressão atualizados com sucesso!", "success")

        # Atualiza a progressão com os pontos adicionados ao clicar em "Salvar Alterações"
        if 'Salvar Alterações' in request.form and not errors:
            db.session.commit()  # Salva todas as alterações na base de dados
            flash("Alterações salvas com sucesso!", "success")
        elif errors:
            flash("Erro ao atualizar os pontos de progressão.", "danger")

    return render_template('progressoes.html', progressoes=progressoes, usuarios=usuarios, usuario_selecionado=usuario_id, errors=errors)




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        for nome in QUALIFICACOES:
            if not Curso.query.filter_by(nome=nome).first():
                curso = Curso(nome=nome)
                db.session.add(curso)
        db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=True)
