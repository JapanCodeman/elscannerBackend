import os
import pymongo
# from bson.objectid import ObjectId #BSON now included with pymongo?
# from bson import json_util
from dotenv import find_dotenv, load_dotenv
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from flask import Flask, jsonify, make_response, Response, request
from flask_cors import CORS
import uuid #use for public_id for simplicity's sake
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv(find_dotenv())

CONNECTION_URL = os.environ.get('CONNECTION_STRING')
SECRET_KEY = os.environ.get('SECRET_KEY')


client = pymongo.MongoClient('CONNECTION_STRING')

app = Flask(__name__) 
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)

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
  client = pymongo.MongoClient(CONNECTION_URL, serverSelectionTimeoutMS = 5000)

except:
  print("Error - cannot connect to database")

Database = client.get_database('ELScanner')

users = Database.users
books = Database.books

registration_codes = {'PGalOv', 'hRYzyu', 'BQiIDP', 'c0J3wM', 'TcLyW3', '5ACsIU', '7KbWKY', 'boCrge', '1oafsV', 'LrTTy6', 'jwYkK3', 'ZH41Ok', '2brnvx', 'xxXkPZ', 'w0QZvA', 'EG9Eus', 'Ne8W4t', 'hq4jCg', 'jZpf7m', 'K51shh', 'ltoRG1', 'BpQ4Ue', 'WG1y0M', 'mQF97I', 'UDHReI', 'N4halH', 'sHVCW1', 'sGKizK', '1H0dnU', 'zc69DB'}

@app.route('/')
def test():
  return html

@app.route('/register', methods=['POST'])
def register(registeration_info):
  first = request.json.get("first")
  last = request.json.get("last")
  email = request.json.get("email")
  password = request.json.get("password")
  registration_code = request.json.get("registration_code")
  logged_status = "False"

  _hashed_password = generate_password_hash(password, method='sha256')

  queryObject = {
    "first": first,
    "last": last,
    "role": 'Instructor',
    "public_id": str(uuid.uuid4()),
    "email": email,
    "password": _hashed_password,
    "logged_in": logged_status
  }
  query = users.insert_one(queryObject)
  return f'{first} {last} and associated data registered to user database as Instructor'

if __name__ == '__main__':
  app.run(debug=True) 