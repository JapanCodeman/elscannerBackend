import datetime
from distutils.log import error
import json
import os
import pymongo
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask import Flask, jsonify, make_response, Response
from flask import request
from flask_cors import CORS, cross_origin
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

ADMIN_CODES = os.environ.get('ADMIN_CODES')
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

  if user["password"] == '':
    return make_response('password-reset', 200)

  if check_password_hash(user["password"], password):
    try:
      token = create_access_token(identity={'userRole' : user['userRole'], 'public_id' : user['public_id'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)})
      return jsonify(token=token)
    except:
      return "Token unable to be distributed", error

  return make_response('Could not verify - end of function', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

# Password Reset
@app.route('/password-reset', methods=['POST'])
def password_reset():
  email_and_password = request.get_json()
  email = email_and_password["email"]
  password = email_and_password["password"]

  user = users.find_one({'email' : email})
  
  if user["password"] == '':
    new_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    users.find_one_and_update({'email' : email}, {"$set" : {
      "password" : new_password
    }})
    return make_response('Password reset successful', 200)

  else:
    return make_response('Password reset unsuccessful', 200)

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
  registerant_info["userRole"] = 'Student'
  registerant_info["wordsRead"] = 0
  registerant_info["totalBooksRead"] = 0
  registerant_info["checkedOutBooks"] = []
  registerant_info["listOfReadBooks"] = []

  users.insert_one(registerant_info)

  return f'{registerant_info["first"]} {registerant_info["last"]} registered to database' 

# Register new admin
@app.route('/register-new-admin', methods=['POST'])
def register_new_admin():
  registerant_info = request.get_json()

  if registerant_info["registrationCode"] in ADMIN_CODES:
    del(registerant_info["registrationCode"])
    del(registerant_info["class"])
    registerant_info["public_id"] = str(uuid.uuid4())
    password = registerant_info["password"]
    _hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    registerant_info["password"] = _hashed_password
    registerant_info["userRole"] = 'Administrator'

    users.insert_one(registerant_info)
  else: #TODO need to fix this response - ADMIN_CODES in .env; heroku has no access
    return Response(
    status=401,
    mimetype="application/json"
  )

  return f'{registerant_info["first"]} {registerant_info["last"]} registered to database as admin' 

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

# Retrieve book title(s) from list
@app.route('/retrieve-checked-out-books', methods=['POST'])
def retrieve_checked_out_books():
  list_of_UPCs = request.get_json()
  title_list = []
  print(f'****************{list_of_UPCs}*******************')

  for UPC in list_of_UPCs["checkedOutBooks"]:
    book_info = books.find_one({"upc" : UPC})
    book_info["_id"] = str(book_info["_id"])
    title_list.append(book_info) 

  return title_list

# Retrieve books with options
@app.route('/retrieve-books', methods=['POST'])
def retrieve_books_with_options():
  params = request.get_json()
  results = books.find({'currentHolder' : params['public_id']}, params['options'])

  return results

# Register or patch new book
@app.route('/register-new-book/<UPC>', methods=['PATCH', 'POST', 'PUT'])
def register_new_book(UPC):

  new_book_info = request.get_json()
  new_book_info['wordCount'] = int(new_book_info['wordCount'])

  books.insert_one(new_book_info)

  return f'{new_book_info} registered to book database'

# Check book back in
@app.route('/check-book-in', methods=['POST'])
def check_book_in():
  student_and_book_UPC = request.get_json()
  print(f'-------->{student_and_book_UPC}<---------')
  student = student_and_book_UPC["studentAndBookUPC"]["student"]
  UPC = student_and_book_UPC["studentAndBookUPC"]["book"]
  book = books.find_one({ 'upc' : UPC })
  wordCount = book["wordCount"]
  books.update_one({ 'upc' : UPC }, {"$set" : {
    "status" : "Checked in",
    "currentHolder" : "Onomichi Gakuen English Library"}})
  users.update_one({ 'public_id' : student }, {"$pull" : {
    "checkedOutBooks" : UPC
  }})
  users.update_one({ 'public_id' : student }, {"$inc" : {
    "totalBooksRead" : 1,
    "wordsRead" : wordCount
  }})

  return f'{UPC} checked in'

# Check book out to student - #TODO
@app.route('/check-book-out', methods=['POST'])
def check_book_out():
  public_id_and_book_upc = request.get_json()
  print(f'*****************{public_id_and_book_upc}***************')
  public_id = public_id_and_book_upc["public_id"]
  book_upc = public_id_and_book_upc["book_upc"]
  student = users.find_one({ 'public_id' : public_id })
  book = books.find_one({'upc' : book_upc})

  users.find_one_and_update({ 'public_id' : public_id }, {"$push" : {"checkedOutBooks" : book_upc}})
  
  books.update_one({ 'upc' : book_upc }, {"$set" : {
    "status" : "Checked Out",
    "currentHolder" : student["public_id"]
  }})

  return f"{book['title']} checked out to {student['first']} {student['last']}"

@app.route('/delete-a-book/<UPC>', methods=['DELETE'])
def delete_a_book(UPC):
  book_to_delete = books.find_one({'upc' : UPC})
  delete_book = books.find_one_and_delete({'upc' : UPC})

  return f'{book_to_delete["title"]} removed from database'
  

if __name__ == "__main__":
  app.run(debug=True)