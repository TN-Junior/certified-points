from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired

class UploadForm(FlaskForm):
    certificate = FileField('Certificate', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 'Certificates only!')
    ])
    submit = SubmitField('Upload')

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    role = SelectField('Role', choices=[('common', 'Comum'), ('admin', 'Admin')])
    submit = SubmitField('Cadastrar')
