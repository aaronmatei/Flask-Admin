from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired


class RegistrationForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    register = SubmitField('Register')
