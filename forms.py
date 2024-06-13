from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField

class UploadForm(FlaskForm):
    certificate = FileField('Certificate', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 'Certificates only!')
    ])
    submit = SubmitField('Upload')
