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

app = Flask(__name__, static_folder='./static')
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)
app.config['JWT_SECRET_KEY'] = SECRET_KEY
jwt = JWTManager(app)

client = pymongo.MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=15000)

Database = client.get_database("ELScanner")

users = Database.users
books = Database.books


@app.route('/db-connect-confirm', methods=['GET'])
def database_connection_test():
  if users.find():
    return True


try:
  if database_connection_test():
    print("Connected to MongoDB Atlas server")
except Exception:
  print("Unable to connect to the server")

@app.route("/")
def test():
  return "ElScanner up and running"

@app.route("/login", methods=["POST"])
def create_token():

  email = request.json.get("email")
  password = request.json.get("password")

  if not email or not password:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  user = users.find_one({"email" : email})

  if not user:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  if check_password_hash(user["password"], password):
    try:
      token = create_access_token(identity={"email" : email, "user" : user["public_id"], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)})
      return jsonify(token=token)
    except:
      return "Token unable to be distributed", error

  return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

# Return all users
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

# Register new user
@app.route('/register-new-user', methods=['POST'])
def register_new_user():
  registerant_info = request.get_json()
  registerant_info["public_id"] = str(uuid.uuid4())
  password = registerant_info["password"]
  _hashed_password = generate_password_hash(password, method='sha256')
  registerant_info["password"] = _hashed_password

  users.insert_one(registerant_info)

  return f'{registerant_info["first"]} {registerant_info["last"]} registered to database' 

# Lookup a user
@app.route('/lookup-user/<public_id>', methods=['GET'])
def lookup_user(public_id):

  user = users.find_one({"public_id" : public_id})
  user["_id"] = str(user["_id"])

  return Response(
    response=json.dumps(user),
    status=200,
    mimetype="application/json"
  )

# Delete a user
@app.route('/delete-a-user/<public_id>', methods=['DELETE'])
def delete_a_user(public_id):
  users.delete_one({"public_id" : public_id})

  return 'User deleted from database'

# DELETE ALL USERS - A-BOMB
@app.route('/delete-all-users', methods=['DELETE'])
def delete_all_users():
  users.delete_many({})

  return 'Users table cleared'

# Retrieve book info
@app.route('/retrieve-book-info/<UPC>', methods=['GET'])
def retrieve_book_info(UPC):
  book_info = books.find_one({"upc" : UPC})
  book_info["_id"] = str(book_info["_id"])
  # held_by = books.find_one({ "currentHolder" : {"$exists" : "true"}}) <--unnecessary? Just include current holder in book object and return that


  return Response(
  response=json.dumps(book_info),
  status=200,
  mimetype="application/json"
)

# Register or patch new book
@app.route('/register-new-book/<UPC>', methods=['PATCH', 'PUT'])
def register_new_book(UPC):

  new_book_info = request.get_json()

  books.insert_one(new_book_info)

  return f'{new_book_info} registered to book database'

# Check book back in
@app.route('/check-book-in/<UPC>', methods=['PATCH'])
def check_book_in(UPC):
  change_book_status = "Checked in"
  books.update_one({ 'upc' : UPC }, {"$set" : {
    "status" : change_book_status,
    "currentHolder" : "Onomichi Gakuen English Library"}})

  return f'{UPC} checked in'

# Check book out to student - #TODO
@app.route('/check-book-out/<UPC>/<public_id>', methods=['PATCH'])
def check_book_out(UPC, public_id):
  student = users.find_one({ 'public_id' : public_id })
  book = books.find_one({'upc' : UPC})

  _checked_out_books = list(student["checkedOutBooks"])
  _checked_out_books.append(UPC)
  
  books.update_one({ 'upc' : UPC }, {"$set" : {
    "status" : "Checked Out",
    "currentHolder" : student["public_id"]
  }})

  users.update_one({ 'public_id' : public_id }, {"$set" : {
    "checkedOutBooks" : _checked_out_books}})

  return f"{book['title']} checked out to {student['first']} {student['last']}"

@app.route('/delete-a-book/<UPC>', methods=['DELETE'])
def delete_a_book(upc):
  book_to_delete = books.find_one({'upc' : upc})
  delete_book = books.find_one_and_delete({'upc' : upc})

  return f'{book_to_delete["title"]} removed from database'
  

if __name__ == "__main__":
  app.run(debug=True)