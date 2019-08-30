from flask import Flask,request,jsonify,make_response
from jsonschema import validate
from jsonschema.exceptions import ValidationError,SchemaError
import jwt
import uuid, datetime
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
app =Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
mongo = PyMongo(app)
app.config['SECREAT_KEY']="thisissecret"

user_schema = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
        },
        "email": {
            "type": "string",
            "format": "email"
        },
        "password": {
            "type": "string",
            "minLength": 5
        }
    },
    "required": ["email", "password"],
    "additionalProperties": False
}


def validate_user(data):
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return {'ok': True, 'data': data}

def token_required(f):
    @wraps (f)
    def decorated(*args,**kwargs):
        token = None
        if'x-access-token' in request.headers:
            token=request.headers['x-access-token']

        if not token:
            return jsonify({'message':'Token is missing!'}),401

        try:
            data = jwt.decode(token,app.config['SECREAT_KEY'])
            current_user = mongo.db.users.find_one({'email': data['email']}, {"_id": 0})
        except:
            return jsonify({'message':'Token is expeired!'}),401
        return f(current_user,*args,**kwargs)    

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    # if not mongo.db.users.find({$and:[ {'email': current_user}, {"role": "admin"}]}):
    #     return jsonify({'message':'Cannot perform that function!'})

    data = mongo.db.users.find()
    return jsonify(data), 200
    

@app.route('/user', methods =['GET'])
@token_required
def get_one_user(current_user):

    # if not mongo.db.users.find({$and:[{'email': current_user}, {"role": "admin"}]}):
    #     return jsonify({'message':'Cannot perform that function!'})

    query = request.args
    data = mongo.db.users.find_one(query)
    return jsonify(data), 200


@app.route('/user', methods=['POST'])

def create_user():

    data= request.get_json()
    data = validate_user(request.get_json())
    if data['ok']:
        data = data['data']
        data['password'] = generate_password_hash(
            data['password'])
        mongo.db.users.insert_one(data)
        return jsonify({'ok': True, 'message': 'User created successfully!'}), 200
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400


@app.route('/user', methods =['PUT'])
@token_required
def edit_user(current_user):

    # if not mongo.db.users.find({$and:[{'email': current_user}, {"role": "admin"}]}):
    #     return jsonify({'message':'Cannot perform that function!'})

    if data.get('query', {}) != {}:
        mongo.db.users.update_one(data['query'], {'$set': data.get('payload', {})})
        return jsonify({'ok': True, 'message': 'record updated'}), 200
    else:

        return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400

@app.route('/user', methods =['DELETE'])
@token_required
def delete_user(current_user):
    # if not mongo.db.users.find({$and:[{'email': current_user}, {"role": "admin"}]}):
    #     return jsonify({'message':'Cannot perform that function!'})

    if data.get('email', None) is not None:
        db_response = mongo.db.users.delete_one({'email': data['email']})
        if db_response.deleted_count == 1:
            response = {'ok': True, 'message': 'record deleted'}
        else:
            response = {'ok': True, 'message': 'no record found'}
        return jsonify(response), 200
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400

@app.route('/login')
def login():
    auth = request.authorization

    idata = validate_user(request.get_json())
    if data['ok']:
        data = data['data']
        user = mongo.db.users.find_one({'email': data['email']}, {"_id": 0})
        LOG.debug(user)
        if user and check_password_hash(user['password'], data['password']):
            del user['password']
            token = jwt.encode({"public_id":user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECREAT_KEY'])
            
            return jsonify({'ok': True, 'data': token.decode('UTF-8')}), 200
        else:
            return jsonify({'ok': False, 'message': 'invalid username or password'}), 401
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400





if __name__ =="__main__":
    app.run(debug=True)