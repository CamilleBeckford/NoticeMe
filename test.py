from flask import Flask,render_template
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] ='mysql://root:noticeMe123@localhost/noticeme'
app.config['SECRET_KEY'] = 'super-secret'

db = SQLAlchemy(app)

class students(db.Model):
   id = db.Column('student_id', db.Integer, primary_key = True)
   name = db.Column(db.String(100))
   city = db.Column(db.String(50))
   addr = db.Column(db.String(200)) 
   pin = db.Column(db.String(10))
    
@app.route("/")
def userlog():
	return render_template('login.html')
    
if __name__ == "__main__":
    app.run(host='192.168.1.3', port=5000, debug=True)