# IMPORTS
import logging
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, current_user, logout_user, login_required
from markupsafe import Markup
from datetime import datetime
from static.helpers import log_invalid_access_attempt, required_roles
from app import db
from models import User
from users.forms import RegisterForm, LoginForm
import bcrypt

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')
admin_blueprint = Blueprint('admin', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()),
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Writes current registration to log
        logging.warning('SECURITY - Registration [%s, %s]',
                        new_user.email,
                        request.remote_addr
                        )

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    # Gets the login form defined in users/forms.py
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Checks to see if the entered information is valid and is an actual account. The user has 3 attempts before they must reset their attempts and try again.
        if not user or not bcrypt.checkpw(form.password.data.encode('utf-8'),
                                          user.password):  # or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            session['authentication_attempts'] += 1
            if session.get('authentication_attempts') >= 3:
                flash(Markup(
                    'Number of incorrect login attempts exceeded. Please click <a href="/reset">here</a> to reset'))
            flash('Either your email, password or pin is incorrect, {} login attempts remaining'.format(
                3 - session.get('authentication_attempts')))

            # Writes invalid login attempt to log
            logging.warning('SECURITY - Invalid log in [%s, %s]',
                            form.email,
                            request.remote_addr
                            )

            return render_template('users/login.html', form=form)
        else:
            # Logs in user with entered details
            login_user(user)

            # Sets the current login time in the database
            user.last_login_time_date = user.cur_login_time_date
            user.cur_login_time_date = datetime.now()
            db.session.commit()

            # Writes the current login to the log file
            logging.warning('SECURITY - Log in [%s, %s, %s]',
                            current_user.id,
                            current_user.email,
                            request.remote_addr
                            )

            # Sends the user to the admin page if they are an admin or to their profile page if not
            if current_user.role == 'admin':
                return redirect(url_for('admin.admin'))
            else:
                return redirect(url_for('users.profile'))

    return render_template('users/login.html', form=form)


# view user profile
@users_blueprint.route('/profile')
@login_required
@required_roles('user')
def profile():
    # Renders the users profile
    return render_template('users/profile.html', name=current_user.firstname + ' ' + current_user.lastname)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    # Renders the users account with their information
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)


# view reset login attempts
@users_blueprint.route('/reset')
@login_required
def reset():
    # Sets the current sessions authentication attempts back to 0 and redirects to the login page
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# view logout user
@users_blueprint.route('/logout')
@login_required
def logout():
    # Writes to the log file the logout information of user
    logging.warning('SECURITY - Log out [%s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    request.remote_addr
                    )

    # Logouts user
    logout_user()

    # Redirects user to index page
    return redirect(url_for('index'))
