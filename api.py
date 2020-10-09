import datetime
import os
import uuid
from functools import wraps

import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Database
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.msg')

# Init db
db = SQLAlchemy(app)

# User Class/Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


# Message Class/Model
class Msg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(20), nullable=False)
    receiver = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    body = db.Column(db.String(150))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    is_message_read = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Welcome page
@app.route('/')
def welcome_page():
    return '<h1>Welcome To Messaging System</h1>'


@app.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:

        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['id'] = user.id
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/msg/<status>', methods=['GET'])
@token_required
def get_all_messages(current_user, status):
    if status == 'all':

        db.session.query(Msg).filter_by(user_id=current_user.id).update({"is_message_read": True})
        db.session.query(Msg).filter_by(receiver=current_user.name).update({"is_message_read": True})
        db.session.commit()

        messages = Msg.query.filter_by(user_id=current_user.id).all() \
                   + Msg.query.filter_by(receiver=current_user.name).all()

        output = []

        for msg in messages:
            msg_data = {}
            msg_data['id'] = msg.id
            msg_data['body'] = msg.body
            msg_data['is_message_read'] = msg.is_message_read
            msg_data['date_posted'] = msg.date_posted
            msg_data['sender'] = msg.sender
            msg_data['receiver'] = msg.receiver
            msg_data['user_id'] = msg.user_id
            msg_data['subject'] = msg.subject

            output.append(msg_data)

        return jsonify({'messages': output})

    if status == 'unread':

        messages = Msg.query.filter_by(user_id=current_user.id, is_message_read=False).all() \
                   + Msg.query.filter_by(receiver=current_user.name, is_message_read=False).all()

        output = []

        for msg in messages:
            msg_data = {}
            msg_data['id'] = msg.id
            msg_data['body'] = msg.body
            msg_data['is_message_read'] = msg.is_message_read
            msg_data['date_posted'] = msg.date_posted
            msg_data['sender'] = msg.sender
            msg_data['receiver'] = msg.receiver
            msg_data['subject'] = msg.subject
            msg_data['user_id'] = msg.user_id

            output.append(msg_data)
            db.session.query(Msg).filter_by(user_id=current_user.id).update({"is_message_read": True})
            db.session.query(Msg).filter_by(receiver=current_user.name).update({"is_message_read": True})

            db.session.commit()
        return jsonify({'messages': output})


@app.route('/msg/<int:msg_id>', methods=['GET'])
@token_required
def get_one_msg(current_user, msg_id):
    msg = Msg.query.filter_by(id=msg_id, user_id=current_user.id).first()

    if not msg:
        return jsonify({'message': 'No msg found!'})

    msg_data = {}
    msg_data['id'] = msg.id
    msg_data['body'] = msg.body
    msg_data['is_message_read'] = msg.is_message_read
    msg_data['date_posted'] = msg.date_posted
    msg_data['sender'] = msg.sender
    msg_data['receiver'] = msg.receiver
    msg_data['receiver'] = msg.receiver
    msg_data['subject'] = msg.subject
    db.session.query(Msg).filter_by(id=msg_id, user_id=current_user.id).update({"is_message_read": True})
    db.session.commit()

    return jsonify(msg_data)


@app.route('/msg', methods=['POST'])
@token_required
def create_msg(current_user):
    data = request.get_json()

    new_msg = Msg(sender=current_user.name, receiver=data['receiver'], subject=data['subject'], body=data['body'],
                  is_message_read=False, user_id=current_user.id)
    db.session.add(new_msg)
    db.session.commit()

    return jsonify({'message': "Message created!"})


@app.route('/msg/<msg_id>', methods=['DELETE'])
@token_required
def delete_msg(current_user, msg_id):
    msg = Msg.query.filter_by(id=msg_id, user_id=current_user.id).first()

    if not msg:
        return jsonify({'message': 'No msg found!'})

    db.session.delete(msg)
    db.session.commit()

    return jsonify({'message': 'Message item deleted!'})


if __name__ == '__main__':
    app.run(threaded=True, port=5000)

