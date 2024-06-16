from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
from urllib.parse import quote as url_quote
import os
from forms import UploadForm

app = Flask(__name__)
app.secret_key = 'alura'
app.config['UPLOAD_FOLDER'] = 'uploads'

def calcular_pontos(certificado):
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

    return pontos

@app.route('/')
def index():
    return render_template('home.html', titulo='Bem-vindo ao Certification')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/autenticar', methods=['POST',])
def autenticar():
    if 'ggie' == request.form['senha']:
        session['usuario_logado'] = request.form['usuario']
        flash(session['usuario_logado'] + ' logado com sucesso!')
        return redirect('/upload')
    else:
        flash('Usuário não logado.')
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
        file = form.certificate.data
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('Certificado enviado com sucesso!')
        return redirect(url_for('upload'))
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('upload.html', form=form, files=files)

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
    usuario = request.form['usuario']
    email = request.form['email']
    senha = request.form['senha']
    # Aqui você deve adicionar a lógica para salvar o usuário no banco de dados
    flash(f'Usuário {usuario} cadastrado com sucesso!')
    return redirect('/login')
app.run(debug=True)
