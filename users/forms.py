import re

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField, ValidationError
from wtforms.validators import Email, EqualTo, DataRequired, Regexp


def check_characters(form, field):
    excluded_characters = "*?!'^+%&/()=}][{$#@<>"

    if field.data == '':
        raise ValidationError("Field must not be empty")

    for character in field.data:
        if character in excluded_characters:
            raise ValidationError("The characters '*?!'^+%&/()=}][{$#@<>' are not allowed")


class RegisterForm(FlaskForm):
    email = EmailField(validators=[Email()])
    firstname = StringField(validators=[check_characters])
    lastname = StringField(validators=[check_characters])
    phone = StringField(validators=[
        Regexp(r'\d{4}[-]\d{3}[-]\d{4}', message="Phone number must be in form XXXX-XXX-XXXX (including dashes)")])
    password = PasswordField(validators=[
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,12}$',
               message="Password requirements: between 6 and 12 characters, at least 1 digit, at least 1 lowercase character, at least 1 uppercase character and at least one special character.")])
    confirm_password = PasswordField(validators=[EqualTo('password', message='Both password fields must match')])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = EmailField(validators=[Email()])
    password = PasswordField(validators=[DataRequired()])
    # pin = StringField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField()
