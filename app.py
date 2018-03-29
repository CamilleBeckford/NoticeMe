from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore,UserMixin, RoleMixin, login_required
##from flask.ext.security.utils import encrypt_password
##from flask.ext.security.registerable import register_user
from datetime import datetime
from flask_table import Table, Col
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, BooleanField, PasswordField,SubmitField,SelectField
from flask_login import current_user
import os
import time
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] ='mysql://root:noticeMe123@localhost/noticeme'
app.config['SECRET_KEY'] = 'super-secret'
##app.config['CSRF_ENABLED'] = True
##app.config['USER_ENABLED_EMAIL'] = False
##app.config['SECURITY_REGISTERABLE'] = True
##app.config['SECURITY_PASSWORD_SALT'] = '0fd571c2653fbbf4126ffcc4fbbffa25'

db= SQLAlchemy(app)

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

# Create a user to test with
@app.before_first_request
def create_user():
    #user_datastore.create_user(email='can@test.fr', password=encrypt_password('testword'))
    #user_datastore.create_user(email='m@nobien.net', password='test')
    db.session.commit()


@app.route("/")
def userlog():
	return render_template('login.html')
    
@app.route("/dashboard",methods=['POST'])
def dashboard():
	username = request.form['username']
	user=User.query.filter_by(email=username).first()
	if User:
		return render_template('dash.html')
	else:
                return render_template('login.html')
@app.route("/dashboard/submit",methods=['POST'])
def submit():
                message=Messages(message=request.form['message'],user_id=1)
		db.session.add(message)
		db.session.commit()
##		os.system("telnet  192.168.1.106 80")
##	time.sleep(6)
		os.system("hey")
		os.system(request.form['message'])
		return render_template('login.html')



if __name__ == '__main__':
    app.run(host='192.168.1.104', port=5001, debug=True)
    app.debug(True)