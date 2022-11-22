# IMPORTS
from datetime import datetime
import bcrypt
import pyotp
from flask_login import UserMixin
from cryptography.fernet import Fernet
from app import db, app


# User Model
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    pinkey = db.Column(db.String(100), nullable=False)
    encryptkey = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    reg_time_date = db.Column(db.DateTime, nullable=False)
    cur_login_time_date = db.Column(db.DateTime, nullable=True)
    last_login_time_date = db.Column(db.DateTime, nullable=True)

    # Define the relationship to Draw
    draws = db.relationship('Draw')

    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.pinkey = pyotp.random_base32()
        self.encryptkey = Fernet.generate_key()
        self.reg_time_date = datetime.now()
        self.cur_login_time_date = None
        self.last_login_time_date = None
        self.role = role


# Draw model
class Draw(db.Model):
    __tablename__ = 'draws'

    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self, user_id, numbers, master_draw, lottery_round):
        self.user_id = user_id
        self.numbers = numbers
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round


# Initialise database
def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.extend_existing = True
        admin = User(email='admin@email.com',
                     password=bcrypt.hashpw('Admin1!'.encode('utf-8'), bcrypt.gensalt()),
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')
        db.session.add(admin)
        db.session.commit()
