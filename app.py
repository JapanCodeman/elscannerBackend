import datetime
from distutils.log import error
import json

import os
import pymongo
from bson.objectid import ObjectId
from bson import json_util
from dotenv import find_dotenv, load_dotenv
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from flask import Flask, jsonify, make_response, Response, request
from flask_cors import CORS
from pymongo import ReturnDocument
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

CONNECTION_STRING = os.environ.get('CONNECTION_STRING')
SECRET_KEY = os.environ.get('SECRET_KEY')

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)

client = pymongo.MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=15000)

Database = client.get_database("ELScanner")

users = Database.users

try:
  print("Connected to MongoDB Atlas server")
except Exception:
  print("Unable to connect to the server")

@app.route("/")
def test():
  return "ElScanner up and running"

@app.route("/login")
def create_token():
  email = request.json.get("email", None)
  password = request.json.get("password", None)

  if not email or not password:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  user = users.find_one({"email" : email})

  if not user:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  if check_password_hash(user["password"], password):
    try:
      token = create_access_token(identity={"email" : email, "role" : user["role"], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)})
      return jsonify(token=token)
    except:
      return "Token unable to be distributed", error

  return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

@app.route('/users', methods=['GET'])
def find_all_users():
  results = list(users.find())
  for user in results:
    user["_id"] = str(user["_id"])

  return Response(
    response=json.dumps(results),
    status=200,
    mimetype="application/json"
  )

if __name__ == "__main__":
  app.run(debug=True)