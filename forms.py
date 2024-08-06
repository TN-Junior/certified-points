'''
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired,NumberRange

class UploadForm(FlaskForm):
    curso = StringField('Curso', validators=[DataRequired()])
    carga_horaria = IntegerField('Carga Horária', validators=[DataRequired(), NumberRange(min=1, message="A carga horária deve ser maior que 0")])
    certificate = FileField('Certificado', validators=[DataRequired(), FileAllowed(['pdf', 'jpg', 'png'], 'Somente arquivos PDF, JPG ou PNG são permitidos!')])
    submit = SubmitField('Enviar')

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    role = SelectField('Role', choices=[('common', 'Comum'), ('admin', 'Admin')])
    submit = SubmitField('Cadastrar')
'''
