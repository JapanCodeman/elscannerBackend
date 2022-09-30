import datetime
from distutils.log import error
from email import message
import json

import os
import pymongo
from bson.objectid import ObjectId
from bson import json_util
from dotenv import find_dotenv, load_dotenv
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask import Flask, jsonify, make_response, Response
from flask import request
from flask_cors import CORS, cross_origin
from pymongo import ReturnDocument
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

CONNECTION_STRING = os.environ.get('CONNECTION_STRING')
SECRET_KEY = os.environ.get('SECRET_KEY')

app = Flask(__name__)

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = SECRET_KEY
cors = CORS(app, supports_credentials=True)
jwt = JWTManager(app)

client = pymongo.MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=15000)

Database = client.get_database("ELScanner")

users = Database.users
books = Database.books


@app.route('/db-connect-confirm', methods=['GET']) # Not working as intended
def database_connection_test():
  if users.find() != None:
    try:
      if database_connection_test():
        return "Connected to MongoDB Atlas server"
    except Exception:
      return "Unable to connect to the server"
  return "Unable to connect to the server - check wifi connection/permissions"

@app.route('/login', methods=["POST"])
@cross_origin(supports_credentials=True)
def login():
  email = request.json.get("email", None)
  password = request.json.get("password", None)
  user = users.find_one({"email" : email})

  if not email or not password:
    return make_response('Could not verify - not email or password', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  if not user:
    return make_response('Could not verify - not user', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  if check_password_hash(user["password"], password):
    try:
      token = create_access_token(identity={"user" : user["public_id"], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)})
      return jsonify(token=token)
    except:
      return "Token unable to be distributed", error

  return make_response('Could not verify - end of function', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

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
  _hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
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

# Get all books
@app.route('/books', methods=['GET'])
def get_all_books():
  all_books = books.find()
  for book in all_books:
    book["_id"] = str(book["_id"])

  return all_books

# Retrieve book info
@app.route('/retrieve-book-info/<UPC>', methods=['GET'])
def retrieve_book_info(UPC):
  if books.count_documents({ 'upc' : UPC }, limit = 1):
    book_info = books.find_one({"upc" : UPC})
    book_info["_id"] = str(book_info["_id"])
  # held_by = books.find_one({ "currentHolder" : {"$exists" : "true"}}) <--unnecessary? Just include current holder in book object and return that

    return Response(
    response=json.dumps(book_info),
    status=200,
    mimetype="application/json"
  )

  return 'Book not registered'

# Register or patch new book
@app.route('/register-new-book/<UPC>', methods=['PATCH', 'POST', 'PUT'])
def register_new_book(UPC):

  new_book_info = request.get_json()
  new_book_info['wordCount'] = int(new_book_info['wordCount'])

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
def delete_a_book(UPC):
  book_to_delete = books.find_one({'upc' : UPC})
  delete_book = books.find_one_and_delete({'upc' : UPC})

  return f'{book_to_delete["title"]} removed from database'
  

if __name__ == "__main__":
  app.run(debug=True)