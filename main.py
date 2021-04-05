from flask import Flask, render_template, redirect, request, flash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
import bcrypt
import os
import boto3
import json
import logging
import sys
import copy
import time
import random
import string
import re
import traceback
from datetime import  datetime
from twilio.twiml.messaging_response import MessagingResponse
from botocore.exceptions import ClientError

if not os.path.isdir('logs'):
    os.mkdir('logs')

log_file = 'logs/{:%Y_%m_%d_%H}.log'.format(datetime.now())
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
app = Flask(__name__)
CSRFProtect(app)
app.config['SECRET_KEY'] = 'QWERFsdd4gefewoihr3wklej;cvohrokdjkjhvjrhwioalicjvkr'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
data_dir = 'data/'
events_file = data_dir + 'events.json'
people_file = data_dir + 'people.json'
bucket = 'pv-ward-sms-manager'
key = os.environ.get('AWS_ACCESS_KEY_ID')
secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
s3 = boto3.client('s3')

orig_time = '%H:%M'
time_format = '%I:%M %p'
date_format = '%m-%d-%Y'
orig_date = '%Y-%m-%d'
max_len = 60
notify_opts = [str(i) for i in range(8)]

if not os.path.isdir(data_dir):
    os.mkdir(data_dir)

'''if not os.path.isfile(events_file):
    with open(events_file, 'w', encoding='utf-8') as f:
        pass

if not os.path.isfile(people_file):
    with open(people_file, 'w', encoding='utf-8') as f:
        pass'''

'''def hash_pass(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())'''

#todo add event/people backups and ability to restore to backup thru website
#todo prob ability to change password

def check_pass(pw):
    return bcrypt.checkpw(str(pw).encode(), pass_hash)

def upload(file=None):
    if file is None:
        to_upload = [events_file, people_file, log_file]
    else:
        to_upload = [file]
    for file in to_upload:
        try:
            with open(file, 'rb') as f:
                s3.upload_fileobj(f, bucket, file)
            logger.info(f'Uploaded {file} to S3 bucket {bucket}')
        except:
            logger.exception(f'Upload of {file} to S3 bucket {bucket} failed')
        if not file.endswith('.log'):
            backup_file = 'backups/' + file.split('/')[1].split('.')[0] + '/' + file.split('/')[1].split('.')[0] + '-' + datetime.now().strftime('%m.%d.%Y-%H:%M:%S') + '.' + file.split('.')[1]
            try:
                with open(file, 'rb') as f:
                    s3.upload_fileobj(f, bucket, backup_file)
                logger.info(f'Uploaded backup file {backup_file} to S3 bucket {bucket}')
            except:
                logger.exception(f'Upload of backup file {backup_file} to S3 bucket {bucket} failed')

def download():
    to_download = [events_file, people_file]
    for file in to_download:
        try:
            with open(file, 'wb') as f:
                s3.download_fileobj(bucket, file, f)
            logger.info(
                f'Downloaded {file} from S3 bucket {bucket}')
        except ClientError:
            logger.info(f'File {file} not found on S3 bucket {bucket}')
            #with open(file, 'w', encoding='utf-8') as f:
            #    pass
            #logger.info(f'Created blank file {file}')
        except:
            logger.exception(
                f'Error downloading file {file} from S3 bucket {bucket}')

def load_people():
    try:
        with open(people_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.info(f'{people_file} not found')
        return {}
    except json.decoder.JSONDecodeError:
        logger.info(f'{people_file} is blank')
        return {}

def format_people():
    if len(people) > 0:
        formatted = {}
        for person in people:
            for group in people[person]['groups']:
                if group not in formatted:
                    formatted[group] = []
                formatted[group].append({'name': person, 'phone': people[person]['phone']})
            formatted[person] = [{'name': person, 'phone': people[person]['phone']}]
        return formatted
    else:
        return None

people = load_people()

def format_event(event):
    #{'formType': 'addEvent', 'eventName': 'test event 1 ', 'eventDate': '04-07-2021', 'eventStartTime': '17:00', 'eventEndTime': '19:00', 'eventLocation': 'trap house', 'eventInvites': ['priests', 'bishoprick'], 'notifyTimes': ['0', '1', '3', '7'], 'start': '05:00 PM', 'end': '07:00 PM'}
    new_event = {'id': ''.join(random.choices(string.ascii_letters, k=10)) + event['eventName'].replace(' ', '_'),
                 'title': event['eventName'], 'date': event['eventDate'], 'start': event['eventStartTime'],
                 'end': event['eventEndTime'], 'location': event['eventLocation'], 'who': event['eventInvites'],
                 'notifyTimes': event['notifyTimes']}
    return new_event

def save_all_events():
    with open(events_file, 'w', encoding='utf-8') as f:
        json.dump(events, f)
    upload(file=events_file)

def save_event(event):
    global events
    event = format_event(event)
    if event['date'] not in events['dates']:
        events['dates'][event['date']] = {'id': 'day-' + event['date'], 'date': event['date'], 'events': []}
    day = event['date']
    del event['date']
    events['dates'][day]['events'].append(event)
    save_all_events()

def load_events():
    try:
        with open(events_file, 'r', encoding='utf-8') as f:
            tmp =  json.load(f)
            logger.info(f'Loaded {len(tmp["dates"])} dates from {events_file}')
            return tmp
    except json.decoder.JSONDecodeError:
        logger.info(f'{events_file} was empty, returning dict with blank date dict')
        return {'dates': {}}
    except FileNotFoundError:
        logger.info(f'{events_file} not found, returning dict with blank date dict')
        return {'dates': {}}

events = load_events()

def format_all_events():
    if len(events['dates']) > 0:
        tmp = copy.deepcopy(events)['dates']
        for t in tmp:
            for e in tmp[t]['events']:
                e['who'] = ', '.join(e['who'])
                e['notifyTimes'] = ', '.join([str(x) for x in e['notifyTimes']]) + ' days before'
        return {k: v for k, v in sorted(tmp.items())}
    else:
        return None

def val_event(event):
    try:
        for e in event:
            if event[e] == '':
                return f'Please add an {e}'
        try:
            event['eventStartTime'] =  datetime.strptime(event['eventStartTime'], orig_time).strftime(time_format)
        except ValueError:
            return 'Please enter a valid start time'
        try:
            event['eventEndTime'] =  datetime.strptime(event['eventEndTime'], orig_time).strftime(time_format)
        except ValueError:
            return 'Please enter a valid end time'
        if datetime.strptime(event['eventEndTime'], time_format).time() < datetime.strptime(event['eventStartTime'], time_format).time():
            return 'The event end time must be after the event start time'
        try:
            event['eventDate'] = datetime.strptime(event['eventDate'], orig_date).strftime(date_format)
        except ValueError:
            return 'Please enter a valid start date'
        if datetime.strptime(event['eventDate'], date_format).date() < datetime.today().date():
            return 'Please enter a date in the future'
        if datetime.strptime(event['eventDate'], date_format).date() == datetime.today().date():
            if datetime.strptime(event['eventStartTime'], time_format).time() < datetime.now().time():
                return 'Please enter a time in the future'
        if len(event['eventName']) > max_len:
            return 'Please enter a shorter event name'
        if len(event['eventLocation']) > max_len:
            return 'Please enter a shorter event location'
        if 'eventInvites' not in event or len(event['eventInvites']) < 1:
            return 'Please select people/groups to invite'
        all_groups = format_people()
        for g in event['eventInvites']:
            if g not in all_groups:
                return 'Invalid group/person detected'
        if len(event['notifyTimes']) < 1:
            return 'Please select when to send notifications'
        for t in event['notifyTimes']:
            if t not in notify_opts:
                return 'Invalid notification time detected'
        return 'success'
    except:
        traceback.print_exc()
        return 'Invalid event, please try again'

def save_all_people():
    with open(people_file, 'w', encoding='utf-8') as f:
        json.dump(people, f)
    upload(file=people_file)

def val_group(group):
    try:
        if len(group['groupMembers']) < 2:
            return 'Please select more than 1 person/group to add to the group'
        if group['groupName'] == '':
            return 'Please enter a group name'
        all_people = format_people()
        for g in group['groupMembers']:
            if g not in all_people:
                #todo maybe error here when only select 1 group/groups?
                return 'Invalid group member detected'
        return 'success'
    except:
        traceback.print_exc()
        return 'Invalid group, please try again'
#todo if i add member and group that already has that member in it, dont do duplicates
def add_group(group):
    global people
    formatted = format_people()
    for member in group['groupMembers']:
        for person in formatted[member]:
            people[person['name']]['groups'].append(group['groupName'])
    save_all_people()

def val_person(person):
    try:
        if person['name'] == '':
            return 'Please enter a name'
        if not person['number'].isnumeric() or len(person['number']) != 10:
            return 'Please enter a valid phone number'
        return 'success'
    except:
        traceback.print_exc()
        return 'Invalid person details, please try again'
#todo add person to group functionality after group creation
def add_person(person):
    global people
    people[person['name']] = {'phone': person['number'], 'groups': []}
    save_all_people()

class User(UserMixin):
    def __init__(self, id=None):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.before_first_request
def setup():
    download()

@app.route('/')
def base():
    return redirect('/login')

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

@app.route('/home', methods=['GET','POST'])
@login_required
def home():
    if request.method == 'POST':
        form = request.form.to_dict(flat=False)
        for f in form:
            if len(form[f]) == 1 and f not in ['eventInvites', 'notifyTimes']:
                form[f] = form[f][0]
        if 'formType' not in form:
            return redirect('/home')
        if form['formType'] == 'addEvent':
            result = val_event(form)
            if result == 'success':
                save_event(form)
                flash('Event added successfully')
            else:
                flash(result)
        if form['formType'] == 'createGroup':
            result = val_group(form)
            if result == 'success':
                add_group(form)
                flash('Group added successfully')
            else:
                flash(result)
        if form['formType'] == 'addPerson':
            result = val_person(form)
            if result == 'success':
                add_person(form)
                flash('Person added successfully')
            else:
                flash(result)
        return redirect('/home')
    return render_template('home.html', title=title, dates=format_all_events(), groups=format_people(), notifyTimes=notify_opts)

@app.route('/settings')
@login_required
def settings():
    #todo settings
    return render_template('settings.html')

@app.route('/sms/msg_recv', methods=['POST'])
def msg_recv():
    resp = MessagingResponse()
    resp.message('test msg 1')
    return str(resp)

if __name__ == '__main__':
    app.run(port=80, debug=True)

