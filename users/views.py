# IMPORTS
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, current_user, logout_user
from markupsafe import Markup
from datetime import datetime
from static.helpers import log_invalid_access_attempt

from app import db
from models import User
from users.forms import RegisterForm, LoginForm
import bcrypt

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')
admin_blueprint = Blueprint('admin', __name__, template_folder='templates')

# Function for writing to log file when an invalid access attempt is made to a page


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if not current_user.is_anonymous:
        log_invalid_access_attempt()
        return render_template('403.html')

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

        # Opens and writes the current registration to the log
        f = open("lottery.log", "a")
        f.write("\nREGISTRATION Email: {email} RequestIP: {requestIP}".format(email=form.email.data, requestIP=request.remote_addr))
        f.close()

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if not current_user.is_anonymous:
        log_invalid_access_attempt()
        return render_template('403.html')

    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user or not bcrypt.checkpw(form.password.data.encode('utf-8'),
                                          user.password):  # or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            session['authentication_attempts'] += 1
            if session.get('authentication_attempts') >= 3:
                flash(Markup(
                    'Number of incorrect login attempts exceeded. Please click <a href="/reset">here</a> to reset'))
                return render_template('users/login.html')
            flash('Either your email, password or pin is incorrect, {} login attempts remaining'.format(
                3 - session.get('authentication_attempts')))

            # Writes invalid login attempt to log
            f = open("lottery.log", "a")
            f.write("\nINVALID LOGIN Email: {email} RequestIP: {requestIP}".format(email=form.email.data, requestIP=request.remote_addr))
            f.close()

            return render_template('users/login.html', form=form)
        else:
            # Logs in user with entered details
            login_user(user)

            # Sets the current login time in the database
            user.cur_login_time_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            db.session.commit()

            # Writes the current login to the log file
            f = open("lottery.log", "a")
            f.write("\nLOGIN UserID: {userID} Email: {email} RequestIP: {requestIP}".format(userID=user.id, email=user.email, requestIP=request.remote_addr))
            f.close()

            # Sends the user to the admin page if they are an admin or to their profile page if not
            if current_user.role == 'admin':
                return redirect(url_for('admin.admin', name=current_user.firstname))
            else:
                return redirect(url_for('users.profile'))

    return render_template('users/login.html', form=form)


# view user profile
@users_blueprint.route('/profile')
def profile():
    if not current_user.is_anonymous and current_user.role == 'user':
        return render_template('users/profile.html', name=current_user.firstname + ' ' + current_user.lastname)
    else:
        log_invalid_access_attempt()
        return render_template('403.html')


# view user account
@users_blueprint.route('/account')
def account():
    if not current_user.is_anonymous:
        return render_template('users/account.html',
                               acc_no=current_user.id,
                               email=current_user.email,
                               firstname=current_user.firstname,
                               lastname=current_user.lastname,
                               phone=current_user.phone)
    else:
        log_invalid_access_attempt()
        return render_template('403.html')


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


@users_blueprint.route('/logout')
def logout():
    if not current_user.is_authenticated:
        log_invalid_access_attempt()
        return redirect(url_for('index'))

    # In the database sets the last login time and date for the current user
    current_user.last_login_time_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    db.session.commit()

    # Writes to the log file the logout information of user
    f = open("lottery.log", "a")
    f.write("\nLOGOUT UserID: {userID} Email: {email} RequestIP: {requestIP}".format(userID=current_user.id, email=current_user.email,
                                                                                      requestIP=request.remote_addr))
    f.close()

    # Logouts user
    logout_user()

    # Redirects user to index page
    return redirect(url_for('index'))
