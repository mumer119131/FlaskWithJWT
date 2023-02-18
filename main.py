from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv

#load the .env file
load_dotenv()

# Created the flask app
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
# Creating the DATABASE model ORM (OBJECT RELATIONAL MAPPING)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    profile = db.relationship('Profile', backref='user', lazy=True, uselist=False) 

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(50))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    address = db.Column(db.String(100))
    phone = db.Column(db.String(20))


    def to_dict(self):
        return {
            'id' : self.id,
            'user_id' : self.user_id,
            'name' : self.name,
            'age' : self.age,
            'gender' : self.gender,
           'address' : self.address,
            'phone' : self.phone
        }
# Creating the token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        # returns 401 error if token isn't passed
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            print(token, app.config['SECRET_KEY'])
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


@app.route('/users', methods= ['GET'])
@token_required
def get_users(current_user):
    
    # get all entries in the users table
    users = User.query.all()

    output = []

    for user in users:
        profile = user.profile
        output.append({ 
            'public_id': user.public_id,
            'email': user.email,
            'profile': profile.to_dict()
        })
    
    return jsonify({'users': output})


# login user
@app.route('/login', methods=['POST'])
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(email= auth.get('email')).first()

    if not user:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
    
    if check_password_hash(user.password, auth.get('password')):
        #generate a jwt token
        token = jwt.encode({
            'public_id': user.public_id,
            'email': user.email,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token' : token, 'data': {
            'email' : user.email,
            
        }}), 201)

    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )


# sinup route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    
    email, password = data.get('email'), data.get('password')
    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            email = email,
            password = generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User created successfully!'}, 201)
    else:
        return jsonify({'message': 'User already exists!'}, 409)


# create profile
@app.route('/profile', methods=['POST'])
@token_required
def create_profile(current_user):
    
    data = request.form
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        profile = Profile(
            user_id = current_user.id,
            name = data.get('name'),
            age = data.get('age'),
            gender = data.get('gender'),
            address = data.get('address'),
            phone = data.get('phone')
        )
        db.session.add(profile)
    else:    
        profile.user_id = current_user.id
        profile.name = data.get('name')
        profile.age = data.get('age')
        profile.gender = data.get('gender')
        profile.address = data.get('address')
        profile.phone = data.get('phone')
    
    db.session.commit()
    return jsonify({'message': 'Profile created successfully!'}, 201)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run( debug= True)
    


    



