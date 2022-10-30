import datetime
from distutils.log import error
import json
import os
import pymongo
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, jwt_required
from flask import Flask, jsonify, make_response, Response
from flask import request
from flask_cors import CORS, cross_origin
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

ENV_ADMIN_CODES = os.environ.get('ADMIN_CODES')
ADMIN_CODES = list(ENV_ADMIN_CODES.split(", ")) # leaving this way for now for testing if editing config vars from within app is possible
CONNECTION_STRING = os.environ.get('CONNECTION_STRING')
SECRET_KEY = os.environ.get('SECRET_KEY')

app = Flask(__name__)

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = SECRET_KEY
cors = CORS(app)
jwt = JWTManager(app)

client = pymongo.MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=15000)

Database = client.get_database("ELScanner")

books = Database.books
classes = Database.classes
users = Database.users

@app.route('/db-connect-confirm', methods=['GET']) 
def database_connection_test():
  if users.find({"userRole" : "Administrator"}):
    try:
      if database_connection_test():
        return "Connected to MongoDB Atlas server"
    except Exception:
      return "Unable to connect to the server"
  return "Unable to connect to the server - check wifi connection/permissions"

@app.route('/login', methods=["POST"])
def login():
  email = request.json.get("email", None)
  email = email.lower()
  password = request.json.get("password", None)
  user = users.find_one({"email" : email})

  if not email or not password:
    return make_response('Could not verify - not email or password', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  if not user:
    return make_response('Could not verify - not user', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

  if user["password"] == '':
    return make_response('password-reset', 200)

  if not check_password_hash(user["password"], password):
    return 'Invalid Password'

  if check_password_hash(user["password"], password):
    try:
      token = create_access_token(identity={'userRole' : user['userRole'], 'public_id' : user['public_id'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)})
      return jsonify(token=token)
    except:
      return "Token unable to be distributed", error

  return make_response('Could not verify - end of function', 401, {'WWW-Authenticate' : 'Basic realm="Login required"'})

# Password Delete
@app.route('/delete-password', methods=['POST'])
def delete_password():
  public_id = request.get_json()
  users.find_one_and_update(public_id, {"$set" : 
  {"password" : ""}})

  return "Password Deleted"

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

# Get all classes
@app.route('/get-all-classes', methods=['GET'])
def get_all_classes():
  all_classes = list(classes.find())
  for _class in all_classes:
    _class["_id"] = str(_class["_id"])

  return Response(
    response=json.dumps(all_classes),
    status=200,
    mimetype="application/json"
  )

# Create new class
@app.route('/create-new-class', methods=['POST'])
def create_new_class():
  new_class = request.get_json()
  new_class["classWordsRead"] = 0
  new_class["classTotalBooksRead"] = 0
  new_class["public_id"] = str(uuid.uuid4())
  new_class["classMembersList"] = []
  new_class["numberOfStudents"] = len(new_class["classMembersList"])

  classes.insert_one(new_class)

  return make_response(f'New class: {new_class["class"]} created', 200)

# Return all users
@app.route('/users', methods=['GET'])
@jwt_required()
def find_all_users():
  results = list(users.find())
  for user in results:
    user["_id"] = str(user["_id"])

  return Response(
    response=json.dumps(results),
    status=200,
    mimetype="application/json"
  )

# Return students in a particular class
@app.route('/students-by-class', methods=['POST'])
def students_by_class():
  classRequest = request.get_json()
  students = users.find(classRequest).sort("first", pymongo.ASCENDING)
  results = []

  for student in students:
    student["_id"] = str(student["_id"])
    results.append(student)

  return make_response(results, 200)

# Register new user
@app.route('/register-new-user', methods=['POST'])
def register_new_user():
  registerant_info = request.get_json()
  if users.find_one({"email" : registerant_info["email"]}):
    return "Email already registered"
  
  registerant_info["public_id"] = str(uuid.uuid4())
  password = registerant_info["password"]
  _hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
  registerant_info["first"] = registerant_info["first"].strip().title()
  registerant_info["last"] = registerant_info["last"].strip().title()
  registerant_info["email"] = registerant_info["email"].strip().lower()
  registerant_info["password"] = _hashed_password
  registerant_info["userRole"] = 'Student'
  registerant_info["wordsRead"] = 0
  registerant_info["totalBooksRead"] = 0
  registerant_info["checkedOutBooks"] = []
  registerant_info["listOfReadBooks"] = []
  _class = classes.find_one_and_update({"class" : registerant_info["class"]},
  {"$push" : {"classMembersList" : registerant_info["public_id"]}})
  _class = classes.find_one_and_update({"class" : registerant_info["class"]},
  {"$inc" : {"numberOfStudents" : 1}})


  users.insert_one(registerant_info)

  return 'Registration successful' 

# Register new admin
@app.route('/register-new-admin', methods=['POST'])
def register_new_admin():
  registerant_info = request.get_json()

  if registerant_info["registrationCode"] in ADMIN_CODES: # how to edit .env variable?

    # Below commented code works for local variables, but not config vars
    # dotenv.unset_key(".env", "ADMIN_CODES") 
    # ADMIN_CODES.remove(registerant_info["registrationCode"])
    # _ADMIN_CODES = ", ".join(ADMIN_CODES)
    # dotenv.set_key(".env", "ADMIN_CODES", _ADMIN_CODES)
    del(registerant_info["registrationCode"])
    del(registerant_info["class"])
    registerant_info["public_id"] = str(uuid.uuid4())
    registerant_info["email"] = registerant_info["email"].strip().lower()
    registerant_info["first"] = registerant_info["first"].strip().title()
    registerant_info["last"] = registerant_info["last"].strip().title()
    password = registerant_info["password"]
    _hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    registerant_info["password"] = _hashed_password
    registerant_info["userRole"] = 'Administrator'

    users.insert_one(registerant_info)
    return "admin registration successful"
  else: #TODO need to fix this response - ADMIN_CODES in .env; heroku has no access
    return "admin registration failed"

# Lookup a user
@app.route('/lookup-user/<public_id>', methods=['GET'])
def lookup_user(public_id):


  user = users.find_one({"public_id" : public_id})
  if user == None:
    return 'User Not Found'

  else:
    user["_id"] = str(user["_id"])

    return Response(
      response=json.dumps(user),
      status=200,
      mimetype="application/json"
    )

# Delete a user
@app.route('/delete-a-user/<public_id>', methods=['DELETE'])
def delete_a_user(public_id):
  user = users.find_one({"public_id" : public_id})
  if user["userRole"] == "Student":
    classes.find_one_and_update({
      {"class" : user["class"]}, {"$pull" : {"classMembersList" : user["public_id"]}}
    })
    classes.find_one_and_update({"class" : user["class"]}, {"$inc" : {
      "numberOfStudents" : -1
    }})
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
@app.route('/register-new-book/<UPC>', methods=['POST', 'PUT'])
def register_new_book(UPC):

  new_book_info = request.get_json()
  new_book_info['wordCount'] = int(new_book_info['wordCount'])

  books.insert_one(new_book_info)

  return f'{new_book_info["title"]} registered to book database'

# Check book back in
@app.route('/check-book-in', methods=['POST'])
def check_book_in():
  student_and_book_UPC = request.get_json()
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
  student_read_book_list = users.find_one({ 'public_id' : student })["listOfReadBooks"]
  
  if UPC not in student_read_book_list:
    users.update_one({ 'public_id' : student }, {"$inc" : {
      "totalBooksRead" : 1,
      "wordsRead" : wordCount
    }})
    users.update_one({ 'public_id' : student }, {"$push" : {
      "listOfReadBooks" : UPC
    }})
    student = users.find_one({ 'public_id' : student})
    classes.update_one({"class" : student["class"]}, {"$inc" : {
      "classWordsRead" : wordCount,
      "classTotalBooksRead" : 1
    }})
  
  if UPC in student_read_book_list:
    users.update_one({ 'public_id' : student }, {"$inc" : {
      "wordsRead" : wordCount
    }})
    student = users.find_one({ 'public_id' : student})
    classes.update_one({"class" : student["class"]}, {"$inc" : {
      "classWordsRead" : wordCount
    }})

  return f'{book["title"]} checked back in from {student["first"]} {student["last"]} - returning to Admin home'

# Check book out to student - #TODO
@app.route('/check-book-out', methods=['POST'])
def check_book_out():
  public_id_and_book_upc = request.get_json()
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

# Delete a book
@app.route('/delete-a-book/<UPC>', methods=['DELETE'])
def delete_a_book(UPC):
  book_to_delete = books.find_one({'upc' : UPC})
  delete_book = books.find_one_and_delete({'upc' : UPC})

  return f'{book_to_delete["title"]} removed from database'

# Lookup individual class info
@app.route('/get-class-info', methods=['POST'])
def get_class_info():
  requested_class = request.get_json()
  _class = classes.find_one(requested_class)
  _class["_id"] = str(_class["_id"])

  return _class

# Return all class info as list of dicts
@app.route('/get-all-classes-info', methods=['GET'])
def get_all_classes_info():
  all_classes_info = classes.find()
  all_classes = []
  for _class in all_classes_info:
    _class["_id"] = str(_class["_id"])
    all_classes.append(_class)
  
  return all_classes

# Update a class
@app.route('/update-class', methods=['POST'])
def update_class():
  class_info = request.get_json() # take in { "public_id" : public_id }
  _update_class = classes.find_one_and_update({
    "public_id" : class_info["public_id"]},
    {"$set" : {"class" : class_info["class"]}},
    return_document=pymongo.ReturnDocument.AFTER)

  return f'Class name updated to {class_info["class"]}'

# Delete a class
@app.route('/delete-class', methods=['DELETE'])
def delete_a_class():
  class_info = request.get_json()
  users.update_many({"class" : class_info["class"]},
  {"$set" : {"class" : ""}})
  classes.find_one_and_delete(class_info)

  return "CLASS_DELETED"
  
# Return all administrators as array
@app.route('/get-all-administrators', methods=['GET'])
def get_all_administrators():
  administrators = users.find({"userRole" : "Administrator"})
  admin = []

  for administrator in administrators:
    administrator["_id"] = str(administrator["_id"])
    admin.append(administrator)
  
  return make_response(admin, 200)

# Get Reader Leaders
@app.route('/get-reader-leaders', methods=['POST'])
def get_reader_leaders():
  reader_leader_request = request.get_json() # just include class in request
  top_three = users.find(reader_leader_request).sort("wordsRead", pymongo.DESCENDING).limit(3)
  _top_three = []
  for student in top_three:
    student["_id"] = str(student["_id"])
    _top_three.append(student)
  return _top_three



if __name__ == "__main__":
  app.run(debug=True)