from flask import Flask, jsonify, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email
import email_validator
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import boto3
from datetime import datetime, timedelta
import random


app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = "THISISKEY"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True )
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_use(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField(label=('Email'), validators=[InputRequired(), Email(), Length(max=120)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

picFolder = os.path.join('static', 'pics')
print(picFolder)
app.config['UPLOAD_FOLDER'] = picFolder

@app.route('/')
def index():
    pic1 = os.path.join(app.config['UPLOAD_FOLDER'], 'logo__4-removebg.png')
    return render_template('index.html', user_image=pic1)


@app.route('/sg_data')
def sg_data():
    # Connect to AWS and get the data
    client = boto3.client('cloudtrail', region_name='us-east-1')
    # Parse the CloudTrail response
    security_groups_created = 0
    security_groups_deleted = 0
    security_groups_modified = 0

    events = ['CreateSecurityGroup', 'DeleteSecurityGroup', 'AuthorizeSecurityGroupIngress',
              'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress']
    # Construct the CloudTrail query

    for evnt in events:
        query = {
            'LookupAttributes': [
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': evnt
                }
            ],
            'MaxResults': 50
        }
        # Run the CloudTrail query
        response = client.lookup_events(**query)

        if evnt == 'CreateSecurityGroup':
            security_groups_created = len(response['Events'])
        elif evnt == 'DeleteSecurityGroup':
            security_groups_deleted = len(response['Events'])
        else:
            security_groups_modified += len(response['Events'])

    data = {'sg_create_count': security_groups_created,
            'sg_delete_count': security_groups_deleted,
            'sg_modify_count': security_groups_modified}
    return jsonify(data)


@app.route('/kms_data')
def kms_data():
    keys = ['Enabled', 'Disabled']
    enabled_count = 0
    disabled_count = 0
    client = boto3.client('kms')
    keys_list = client.list_keys()
    for key in keys_list["Keys"]:
        rotation_response = client.get_key_rotation_status(
            KeyId=str(key["KeyId"])
        )
        if(rotation_response["KeyRotationEnabled"] is True):
            enabled_count+=1
        else:
            disabled_count+=1
    rotation_count = [enabled_count, disabled_count] 

    return jsonify({
        'keys': keys,
        'rotation_count': rotation_count,
    })



@app.route('/get_events_data/<int:top_n>')
def get_events_data(top_n):
    cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')

    # Get a list of all CloudTrail events
    events_response = cloudtrail.lookup_events()

    # Initialize a dictionary to store event names and counts
    event_counts = {}

    # Loop through each event and count occurrences
    for event in events_response['Events']:
        event_name = event['EventName']
        if event_name in event_counts:
            event_counts[event_name] += 1
        else:
            event_counts[event_name] = 1

    # Sort the events by count and take the top N
    sorted_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    # Extract the event names and counts into separate lists
    event_names = [event[0] for event in sorted_events]
    event_counts = [event[1] for event in sorted_events]

    # Combine event names and counts into a dictionary
    data = {
        'event_names': event_names,
        'event_counts': event_counts
    }

    return jsonify(data)

@app.route('/ec2_data')
def ec2_data():
    cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')

    # Get a list of all CloudTrail events
    events_response = cloudtrail.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'EventSource',
                'AttributeValue': 'ec2.amazonaws.com'
            }
        ]
    )

    # Initialize a dictionary to store event names and counts
    data = {
        "RunInstances": 0,
        "StartInstances": 0,
        "StopInstances": 0,
        "TerminateInstances": 0
    }

    # Loop through each event and count occurrences
    for event in events_response['Events']:
        event_name = event['EventName']
        print(event_name)
        if event_name in data:
            print(event_name)
            data[event_name] += 1
    token=events_response['NextToken']
    for i in range(10):
         # Get a list of all CloudTrail events
        events_response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventSource',
                    'AttributeValue': 'ec2.amazonaws.com'
                }
            ],
            NextToken=token
        )
        token=events_response['NextToken']
        # Loop through each event and count occurrences
        for event in events_response['Events']:
            event_name = event['EventName']
            print(event_name)
            if event_name in data:
                print(event_name)
                data[event_name] += 1
    print("Data: ", data)
    return jsonify(data)

@app.route('/ec2')
def ec2():
    return render_template('ec2.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                #user.password == form.password.data:
                return redirect(url_for('dashboard'))
        return '<h1> Invalid Username and Password </h1>'
       # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1> '

    pic1 = os.path.join(app.config['UPLOAD_FOLDER'], 'logo__4-removebg.png')
    return render_template('login.html', user_image=pic1, form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
       # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + ' </h1>'
       hashed_password = generate_password_hash(form.password.data, method='sha256')
       new_user = User(username=form.username.data, email=form.email.data, password=hashed_password) #to text I will update it hash password
       db.session.add(new_user)
       db.session.commit()

       return '<h1> New user has been created! </h1>'
    pic1 = os.path.join(app.config['UPLOAD_FOLDER'], 'logo__4-removebg.png')
    return render_template('signup.html', user_image=pic1, form=form)


@app.route('/charts')
def charts():
    return render_template('charts.html')

@app.route('/events_chart')
def top_events():
    return render_template('events_chart.html')

@app.route('/kms')
def kms():
    return render_template('kms_graph.html')

@app.route('/dashboard')
@login_required

def dashboard():
    client = boto3.client('cloudtrail', region_name='us-east-1')
    # List all events for a specific trail
    # List all trails
    response = client.lookup_events()
    print(response)
    events=[]
    for event in response['Events']:
        events.append({
            'event_id': event['EventId'],
            'event_name': event['EventName'],
            'event_time': event['EventTime'],
            'event_detail': event['CloudTrailEvent'],
        })
        print("Event: ", event['EventId'])
    # Render the template with the events data
    print(events)
    return render_template('dashboard.html', name=current_user.username, events=events)

@app.route('/logout')

@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)

app.config['ENV'] = 'development'
app.config['DEBUG'] = True
app.config['TESTING'] = True