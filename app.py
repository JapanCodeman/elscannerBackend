import os
import pymongo
# from bson.objectid import ObjectId #BSON now included with pymongo?
# from bson import json_util
from bson import json_util
from dotenv import find_dotenv, load_dotenv
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from flask import Flask, jsonify, make_response, Response, Request, request
from flask_cors import CORS
import json
from pymongo import mongo_client
import uuid #use for public_id for simplicity's sake
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv(find_dotenv())

CONNECTION_STRING = os.getenv('CONNECTION_STRING')
SECRET_KEY = os.getenv('SECRET_KEY')


client = pymongo.MongoClient(CONNECTION_STRING)

app = Flask(__name__) 
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)

# print("THIS IS THE CONNECTION URL", CONNECTION_URL)
# print("THIS IS THE SECRET_KEY", SECRET_KEY)
app.config['JWT_SECRET_KEY'] = SECRET_KEY
jwt = JWTManager(app)

html = '''
<!doctype html>
<html>
  <head>
    <title>ELScanner Backend</title>
  </head>
  <body>
    <p>Backend for ELScanner is running</p>
  </body>
</html>
'''


try:
  client = pymongo.MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS = 5000)

except:
  print("Error - cannot connect to database")

Database = client.get_database("ELScanner")

users = Database.users
books = Database.books

registration_codes = set({'PGalOv', 'hRYzyu', 'BQiIDP', 'c0J3wM', 'TcLyW3', '5ACsIU', '7KbWKY', 'boCrge', '1oafsV', 'LrTTy6', 'jwYkK3', 'ZH41Ok', '2brnvx', 'xxXkPZ', 'w0QZvA', 'EG9Eus', 'Ne8W4t', 'hq4jCg', 'jZpf7m', 'K51shh', 'ltoRG1', 'BpQ4Ue', 'WG1y0M', 'mQF97I', 'UDHReI', 'N4halH', 'sHVCW1', 'sGKizK', '1H0dnU', 'zc69DB'})


# Test route
@app.route('/')
def test():
  return html


# Basic login route
@app.route('/login', methods=['POST'])
def create_token():
  email = Request.json.get('email')
  password = Request.json.get('password')

  if not email or not password:
    return f'Email or password missing - unable to distribute token'
  
  user = users.find_one({'email': email})
 
  if not user:
    return f'User not found - unable to distribute token'

  if check_password_hash(user['password'], password):
    try:
      token = create_access_token(identity={user})
      return jsonify(token=token)

    except:
      return f'Unable to distribute token'


# Register an instructor/instructor-admin - requires valid registration code
@app.route('/register', methods=["POST"])
def register():
  first = request.json.get("first", None)
  last = request.json.get("last", None)
  email = request.json.get("email", None)
  password = request.json.get("password", None)
  registration_code = request.json.get("registration_code", None)

  _hashed_password = generate_password_hash(password, method='sha256')

  queryObject = {
    "first": first,
    "last": last,
    "role": 'Instructor',
    "public_id": str(uuid.uuid4()),
    "email": email,
    "password": _hashed_password,
    "registration_code": registration_code,
    "loggedStatus": "NOT_LOGGED_IN",
    "isAdmin": "NOT_ADMIN"
  }

  if registration_code in registration_codes:
    query = users.insert_one(queryObject)
    return f'{first} {last} and associated data registered to user database as Instructor'
  else:
    return f'Invalid instructor registration code'

# Register one student
@app.route('/register-student', methods=['POST'])
def register_student():
  first = Request.get_json("first")
  last = Request.get_json("last")
  
  email = Request.get_json("email")
  checked_out_list = Request.get_json("checkedOutList")

  query_object = {
    "first": first,
    "last": last,
    "email": email,
    "public_id": str(uuid.uuid4()),
    "checkedOutList": checked_out_list
  }

# @app.route('/register-book', methods=['POST'])
# def register_book():


if __name__ == '__main__':
  app.run(debug=True) 