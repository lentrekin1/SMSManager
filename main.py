from flask import Flask, render_template, redirect, request, flash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
import bcrypt
import os
import csv
import logging
import sys
from datetime import  datetime
from twilio.twiml.messaging_response import MessagingResponse

if not os.path.isdir('logs'):
    os.mkdir('logs')

log_file = 'logs\{:%Y_%m_%d_%H}.log'.format(datetime.now())
log_format = u'%(asctime)s | %(levelname)-8s | %(message)s'
logger = logging.getLogger('PV Ward YM SMS Scheduler')
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(log_file, encoding='utf-8')
formatter = logging.Formatter(log_format)
handler.setFormatter(formatter)
logger.addHandler(handler)
printer = logging.StreamHandler(sys.stdout)
printer.setLevel(logging.DEBUG)
printer.setFormatter(formatter)
logger.addHandler(printer)

title = 'Palo Verde ward SMS scheduler'
pass_hash = b'$2b$12$c.GLgp2C3bpXfXIYxZ/z0eOe9bjV7xQpCTz1lo/Q9lGZLMsunD5U2' # pvymarecool
events_file = 'events.csv'
#https://www.cssscript.com/feature-rich-event-calendar/
event_fields = ['id', 'title', 'from', 'to', 'description', 'location', 'color', 'colorText', 'colorBorder', 'isAllDay', 'repeatEver', 'repeatEveryExcludedDays', 'seriesIgnoreDates', 'created', 'organizerName', 'organizerEmailAddress', 'repeatEnds']
app = Flask(__name__)
app.config['SECRET_KEY'] = 'QWERFsdd4gefewoihr3wklej;cvohrokdjkjhvjrhwioalicjvkr'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

'''def hash_pass(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())'''

def check_pass(pw):
    return bcrypt.checkpw(str(pw).encode(), pass_hash)

def load_events():
    if not os.path.isfile(events_file):
        with open(events_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(event_fields)
        logger.info(f'Events file {events_file} not found, created it with row names {event_fields}')

    tmp = []
    with open(events_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            tmp.append({k: v for k, v in row.items() if v is not None and v != ''})
        logger.info(f'Read {len(tmp)} events from {events_file}')
    return tmp

events = load_events()

class User(UserMixin):
    def __init__(self, id=None):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def base():
    return redirect('/login')
#todo prob use https://getbootstrap.com/docs/4.0/components/collapse/ (accordian example) to display already created events
#todo panels not showing correctly
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')
    if request.method == 'POST':
        if check_pass(request.form.get('pass')):
            login_user(User())
            return redirect('/home')
        else:
            flash('Incorrect password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/home')
@login_required
def home():
    return render_template('home.html', title=title)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/sms/msg_recv', methods=['POST'])
def msg_recv():
    resp = MessagingResponse()
    resp.message('test msg 1')
    return str(resp)


if __name__ == '__main__':
    app.run(port=80, debug=True)
