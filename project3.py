import os
import uuid
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from argon2 import PasswordHasher
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('NOT_MY_KEY')

db = SQLAlchemy(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per second"]
)

ph = PasswordHasher()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def __repr__(self):
        return '<User %r>' % self.username


class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(45), nullable=False)
    request_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    user = db.relationship('User', backref=db.backref('auth_logs', lazy=True))


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    user = User(username=username, email=email, password_hash=password_hash)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 400

    return jsonify({'password': password}), 201


@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user is None or not ph.verify(user.password_hash, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    auth_log = AuthLog(request_ip=request.remote_addr, user_id=user.id)
    db.session.add(auth_log)
    db.session.commit()

    return jsonify({'message': 'Authentication successful'})


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
