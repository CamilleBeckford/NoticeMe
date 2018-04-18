from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore,UserMixin, RoleMixin, login_required
##from flask.ext.security.utils import encrypt_password
##from flask.ext.security.registerable import register_user
from datetime import datetime
from flask_table import Table, Col
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, BooleanField, PasswordField,SubmitField,SelectField
from flask_login import current_user, LoginManager, UserMixin, login_user, login_required, logout_user
import os
import time
import socket
import paho.mqtt.client as mqtt
import sys

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] ='mysql://root:noticeMe123@localhost/noticeme'
app.config['SECRET_KEY'] = 'super-secret'
##app.config['CSRF_ENABLED'] = True
##app.config['USER_ENABLED_EMAIL'] = False
##app.config['SECURITY_REGISTERABLE'] = True
##app.config['SECURITY_PASSWORD_SALT'] = '0fd571c2653fbbf4126ffcc4fbbffa25'

db= SQLAlchemy(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
displays=['HallLT','RossLT']
times=['0.5','1','5','15','30','45','60']
myip="172.16.188.80"
broker_address=myip
resp=''
client=mqtt.Client("Server")


# Define models
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    messages= db.relationship('Messages',backref='user',lazy=True)

class Messages (db.Model):
	__tablename__='messages'
	id = db.Column(db.Integer, primary_key=True)
	message = db.Column(db.String(255))
	date = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
	duration= db.Column(db.Integer)
	user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
	displays=db.relationship('Displays',backref='messages',lazy=True)

class Displays(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	status = db.Column(db.String(255))
	message_id=db.Column(db.Integer,db.ForeignKey('messages.id'),nullable=False)
	
 

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create a user to test with
@app.before_first_request
def create_user():
    #user_datastore.create_user(email='can@test.fr', password=encrypt_password('testword'))
    #user_datastore.create_user(email='m@nobien.net', password='test')
    db.session.commit()


@app.route("/")
def userlog():
	return render_template('login.html')
    
    
def piesend(message):
    
    print("Creating new instance")
    ##	client.on_message=on_message
    print("Connecting to broker")
    client.connect(broker_address)
    client.loop_start()
    client.subscribe("RossLT")
    client.publish("RossLT",message)
    print("Publish")
    time.sleep(4)
    client.loop_stop()
    
def megasend(message):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address=('192.168.0.101',80)
    sock.connect(server_address)
    try:
                    #message= 'ESp'+request.form['message']
                        #mess=str(request.form['message'])
        mess='esp'+message
        sock.sendall(mess.encode('utf-8'))
                    #sock.sendall(bytes(mess,'utf-8'))
        amount_recieved=0
                  
        amount_expected= len(mess)
    finally:
        sock.close()
        
def on_message(client,userdata,message):
    resp=message.payload.decode("utf-8")
    print("message recieved", str(message.payload.decode("utf-8")))
    
    
@app.route("/dashboard",methods=['POST'])
def dashboard():
	username = request.form['username']
	user=User.query.filter_by(email=username).first()
	chatinz=Messages.query.filter_by(user_id=user.id)
	if user:
                
		return render_template('dash.html',displays=displays, times=times, chatinz=chatinz)
	else:
                return render_template('login.html')
            
@app.route("/dashboard/submit",methods=['POST'])
def submit():
                message=Messages(message=request.form['message'],user_id=1)
		db.session.add(message)
		db.session.commit()
		screen=request.form['displays']
		
		print(str(request.form['displays']))
		if(screen==displays[0]):
                    megasend(request.form['message'])
                    
                else:
                    piesend(request.form['message'])
                    print("Connecting to broker")
                    client.connect(broker_address)
                    client.loop_start()
                    client.subscribe("RossResp")
                    client.on_message=on_message
                    time.sleep(4)
                    client.loop_stop()
                if resp=='OK':
                    print 'Message recieved'
                    
                   
		return render_template('dash.html',displays=displays, times=times)



if __name__ == '__main__':
    app.run(host=myip, port=5000, debug=True)
    app.debug(True) 