from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.utils import secure_filename
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

app.run(debug=True)
