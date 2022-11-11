import re

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField, ValidationError
from wtforms.validators import Email, EqualTo, NoneOf, DataRequired


def check_characters(form, field):
    excluded_characters = "*?!'^+%&/()=}][{$#@<>"

    for character in field.data:
        if character in excluded_characters:
            raise ValidationError("The characters '*?!'^+%&/()=}][{$#@<>' are not allowed")


class RegisterForm(FlaskForm):

    def validate_password(self, password):
        p = re.compile('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,12}$')
        if not p.match(password.data):
            raise ValidationError("Password does not meet requirements")

    def validate_phone(self, phone):
        p = re.compile('\d{4}[-]\d{3}[-]\d{4}')
        if not p.match(phone.data):
            raise ValidationError("Phone number must be in form XXXX-XXX-XXXX (including dashes)")

    email = EmailField(validators=[Email()])
    firstname = StringField(validators=[check_characters])
    lastname = StringField(validators=[check_characters])
    phone = StringField(validators=[])
    password = PasswordField(validators=[])
    confirm_password = PasswordField(validators=[EqualTo('password', message='Both password fields must match')])
    submit = SubmitField()

class LoginForm(FlaskForm):
    email = EmailField(validators=[Email()])
    password = PasswordField(validators=[DataRequired()])
    #pin = StringField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField()
