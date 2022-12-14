# IMPORTS
import logging

from cryptography.fernet import Fernet
from static.helpers import encrypt, decrypt, log_invalid_access_attempt, required_roles
from flask import Blueprint, render_template, request, flash
from flask_login import current_user, login_required

from app import db
from models import Draw

# CONFIG
lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@login_required
@required_roles('user')
def lottery():
    return render_template('lottery/lottery.html')


# adding a draw
@lottery_blueprint.route('/add_draw', methods=['POST'])
@login_required
@required_roles('user')
def add_draw():
    # get new draw entered in form
    submitted_draw = ''
    for i in range(6):
        # Get number from input field and add to draw
        submitted_draw += request.form.get('no' + str(i + 1)) + ' '
    # remove any surrounding whitespace
    submitted_draw.strip()

    # create a new draw with the form data.
    new_draw = Draw(user_id=current_user.id,
                    numbers=encrypt(submitted_draw, current_user.encryptkey), master_draw=False,
                    lottery_round=0)

    # add the new draw to the database
    db.session.add(new_draw)
    db.session.commit()

    # re-render lottery.page
    flash('Draw %s submitted.' % submitted_draw)
    return lottery()


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@login_required
@required_roles('user')
def view_draws():
    # get all draws that have not been played [played=0]
    playable_draws = Draw.query.filter_by(been_played=False,
                                          user_id=current_user.id).all()

    # if playable draws exist
    if len(playable_draws) != 0:
        # decrypts each draws numbers
        for draw in playable_draws:
            draw.numbers = decrypt(draw.numbers, current_user.encryptkey)

        # re-render lottery page with playable draws
        return render_template('lottery/lottery.html',
                               playable_draws=playable_draws)
    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@login_required
@required_roles('user')
def check_draws():
    # get played draws
    played_draws = Draw.query.filter_by(been_played=True, user_id=current_user.id).all()

    # if played draws exist
    if len(played_draws) != 0:
        return render_template('lottery/lottery.html', results=played_draws, played=True)

    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# delete all played draws
@lottery_blueprint.route('/play_again', methods=['POST'])
@login_required
@required_roles('user')
def play_again():
    Draw.query.filter_by(been_played=True, master_draw=False).delete(synchronize_session=False)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()
