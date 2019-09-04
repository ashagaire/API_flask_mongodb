from flask import Flask,request,jsonify,make_response
from jsonschema import validate
from jsonschema.exceptions import ValidationError,SchemaError
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import JWTManager
import uuid, datetime
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from functools import wraps
import json
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

app =Flask(__name__)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, set):
            return list(o)
        if isinstance(o, datetime.datetime):
            return str(o)
        return json.JSONEncoder.default(self, o)

app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
mongo = PyMongo(app)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['SECREAT_KEY']="thisissecret"
jwt = JWTManager(app)
app.json_encoder = JSONEncoder

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
    "additionalProperties": True
}

def validate_user(data):
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return {'ok': True, 'data': data}

@app.route('/user', methods=['GET'])
@jwt_required
def get_all_users():
    current_user = get_jwt_identity()
    
    if not mongo.db.users.find_one({'$and':[{'email': current_user['username']},{"role": "admin"}]}):
        return jsonify({'message':'Cannot perform that function!'})
    else:    
        query = request.args
        if query:
            data = mongo.db.users.find_one(query,{"_id": 0})
            return jsonify({'ok': True, 'data': data}), 200
        else:
            data = [doc for doc in mongo.db.users.find()]
            return jsonify({'ok': True, 'data': data}), 200

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


@app.route('/user', methods =['PATCH'])
@jwt_required
def edit_user():
    current_user = get_jwt_identity()

    if not mongo.db.users.find_one({'$and':[{'email': current_user['username']},{"role": "admin"}]}):
        return jsonify({'message':'Cannot perform that function!'})
    else:
        data = request.get_json()
        if data.get('query', {}) != {}:
            mongo.db.users.update_one(data['query'], {'$set': data.get('payload', {})})
            return jsonify({'ok': True, 'message': 'record updated'}), 200
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400

@app.route('/user', methods =['DELETE'])
@jwt_required
def delete_user():
    current_user = get_jwt_identity()

    if not mongo.db.users.find_one({'$and':[{'email': current_user['username']},{"role": "admin"}]}):
        return jsonify({'message':'Cannot perform that function!'})
    else:
        data = request.get_json()
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
    data = request.authorization
    if not data or not data.username or not data.password:
        return make_response("Could not verify",401,{'WWW-Authenticate':'Basic realm="Login Required"'})
    else:
        user = mongo.db.users.find_one({'email': data.username})
        
        if user and check_password_hash(user['password'], data.password):
            token = create_access_token(identity=data)
            user['token'] = token
            return jsonify({'ok': True, 'data': user}), 200
        else:
            return jsonify({'ok': False, 'message': 'invalid username or password'}), 401

if __name__ =="__main__":
    app.run(debug=True)