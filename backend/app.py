from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import os
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# Load environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///permits.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Permit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(50), nullable=False)
    truck_details = db.Column(db.String(255), nullable=False)
    route = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            jwt.decode(token.split(" ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/submit_permit', methods=['POST'])
@token_required
def submit_permit():
    data = request.json
    new_permit = Permit(state=data['state'], truck_details=data['truck_details'], route=data['route'])
    db.session.add(new_permit)
    db.session.commit()
    return jsonify({'message': 'Permit submitted successfully'}), 201

@app.route('/permit_status', methods=['GET'])
@token_required
def get_permit_status():
    permits = Permit.query.all()
    output = [{'id': p.id, 'state': p.state, 'truck_details': p.truck_details, 'route': p.route, 'status': p.status, 'created_at': p.created_at} for p in permits]
    return jsonify(output)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
    