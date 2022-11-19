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
from flask_talisman import Talisman
from random import randint
from requests import HTTPError
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

ENV_ADMIN_CODES = os.environ.get('ADMIN_CODES')
# leaving this way for now for testing if editing config vars from within app is possible
ADMIN_CODES = list(ENV_ADMIN_CODES.split(", "))
CONNECTION_STRING = os.environ.get('CONNECTION_STRING')
SECRET_KEY = os.environ.get('SECRET_KEY')
PASSWORD_RESET_CODES = list(os.environ.get('PASSWORD_RESET_CODES').split(", "))

app = Flask(__name__)

# Config options
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
cors = CORS(app, supports_credentials=True)
jwt = JWTManager(app)
Talisman(app, content_security_policy=None)

client = pymongo.MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=15000)

Database = client.get_database("ELScanner")

books = Database.books
classes = Database.classes
users = Database.users


### START OF ROUTES ###

@app.route('/login', methods=["POST"])
@cross_origin(supports_credentials=True)
def login():
    username = request.json.get("username", None)
    username = username.lower()
    password = request.json.get("password", None)
    user = users.find_one({"username": username})

    if not username:
        return make_response('Could not verify - username required', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if user == None:
        return make_response('USER_NOT_FOUND', 200)

    if user["passwordReset"] == True and check_password_hash(user["password"], password):
        token = create_access_token(identity=(
            {'userRole': user['userRole'], 'public_id': user['public_id']}), fresh=(True))
        return jsonify(token=token, data='PASSWORD_RESET')

    if user["passwordReset"] == True and not check_password_hash(user["password"], password):
        return make_response('INVALID_PASSWORD', 200)

    if not check_password_hash(user["password"], password):
        return 'INVALID_PASSWORD'

    if check_password_hash(user["password"], password):
        try:
            if user["password"] in PASSWORD_RESET_CODES:
                token = create_access_token(identity=(
                    {'userRole': user['userRole'], 'public_id': user['public_id']}), fresh=(True))
                return jsonify(token=token, data='PASSWORD_RESET')
            else:
                token = create_access_token(identity=(
                    {'userRole': user['userRole'], 'public_id': user['public_id']}), fresh=(True))
                return jsonify(token=token)
        except:
            return "Token unable to be distributed", error

    return make_response('Could not verify - end of function', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

# Password Delete


@app.route('/delete-password', methods=['POST'])
@jwt_required(fresh=True)
def delete_password():
    public_id = request.get_json()
    temp_password = PASSWORD_RESET_CODES[randint(1, 50)]
    users.find_one_and_update(public_id, {"$set":
                                          {"password": generate_password_hash(temp_password, method='pbkdf2:sha256', salt_length=16)}})
    if check_password_hash(users.find_one(public_id)['password'], temp_password):
        users.find_one_and_update(public_id, {"$set":
                                              {"passwordReset": True}})

        return {
            "message": "PASSWORD_RESET",
            "temporaryPassword": temp_password
        }

    return "PASSWORD_RESET_ABORTED"

# Password Reset


@app.route('/password-reset', methods=['POST'])
@jwt_required(fresh=True)
def password_reset():
    username_and_password = request.get_json()
    username = username_and_password["username"].lower()
    password = username_and_password["password"]

    user = users.find_one({'username': username})

    if user["passwordReset"] == True:
        new_password = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=16)
        users.find_one_and_update({'username': username}, {"$set": {
            "password": new_password
        }})
        users.find_one_and_update({'username': username}, {"$set": {
            "passwordReset": False
        }})
        # must return token here
        return make_response('Password reset successful', 200)

    else:
        return make_response('Password reset unsuccessful', 200)

# Get all classes


@app.route('/get-all-classes', methods=['GET'])
@jwt_required(fresh=True)
def get_all_classes():
    all_classes = list(classes.find())
    for _class in all_classes:
        _class["_id"] = str(_class["_id"])

    return Response(
        response=json.dumps(all_classes),
        status=200,
        mimetype="application/json"
    )

# Get all classes - class name only


@app.route('/get-all-class-names', methods=['GET'])
def get_all_class_names():
    all_classes = list(classes.find())
    class_names = []
    for _class in all_classes:
        class_names.append(_class["class"])

    return Response(
        response=json.dumps(class_names),
        status=200,
        mimetype="application/json"
    )

# Create new class


@app.route('/create-new-class', methods=['POST'])
@jwt_required(fresh=True)
def create_new_class():
    try:
        new_class = request.get_json()
        new_class["classWordsRead"] = 0
        new_class["classTotalBooksRead"] = 0
        new_class["public_id"] = str(uuid.uuid4())
        new_class["classMembersList"] = []
        new_class["numberOfStudents"] = len(new_class["classMembersList"])

        classes.insert_one(new_class)

        return make_response(f'New class: {new_class["class"]} created', 200)

    except (HTTPError):
        return make_response('SESSION_TIMEOUT', 401)

# Return students in a particular class


@app.route('/students-by-class', methods=['POST'])
@jwt_required(fresh=True)
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
    if users.find_one({"username": registerant_info["username"]}):
        return "username already registered"

    registerant_info["public_id"] = str(uuid.uuid4())
    password = registerant_info["password"]
    _hashed_password = generate_password_hash(
        password, method='pbkdf2:sha256', salt_length=16)
    registerant_info["first"] = registerant_info["first"].strip().title()
    registerant_info["last"] = registerant_info["last"].strip().title()
    registerant_info["username"] = registerant_info["username"].strip().lower()
    registerant_info["password"] = _hashed_password
    registerant_info["passwordReset"] = False
    registerant_info["userRole"] = 'Student'
    registerant_info["wordsRead"] = 0
    registerant_info["totalBooksRead"] = 0
    registerant_info["checkedOutBooks"] = []
    registerant_info["listOfReadBooks"] = []
    classes.find_one_and_update({"class": registerant_info["class"]},
                                {"$push": {"classMembersList": registerant_info["public_id"]}})
    classes.find_one_and_update({"class": registerant_info["class"]},
                                {"$inc": {"numberOfStudents": 1}})

    users.insert_one(registerant_info)

    return 'Registration successful'

# Register new student from Admin - with blank password field for student to set


@app.route('/admin-register-new-user', methods=['POST'])
def admin_register_new_student():
    registerant_info = request.get_json()
    temp_password = PASSWORD_RESET_CODES[randint(1, 50)]
    if users.find_one({"username": registerant_info["username"]}):
        return "username already registered"

    registerant_info["public_id"] = str(uuid.uuid4())
    registerant_info["first"] = registerant_info["first"].strip().title()
    registerant_info["last"] = registerant_info["last"].strip().title()
    registerant_info["username"] = registerant_info["username"].strip().lower()
    registerant_info["password"] = generate_password_hash(
        temp_password, method='pbkdf2:sha256', salt_length=16)
    registerant_info["passwordReset"] = False
    registerant_info["userRole"] = 'Student'
    registerant_info["wordsRead"] = 0
    registerant_info["totalBooksRead"] = 0
    registerant_info["checkedOutBooks"] = []
    registerant_info["listOfReadBooks"] = []
    classes.find_one_and_update({"class": registerant_info["class"]},
                                {"$push": {"classMembersList": registerant_info["public_id"]}})
    classes.find_one_and_update({"class": registerant_info["class"]},
                                {"$inc": {"numberOfStudents": 1}})

    users.insert_one(registerant_info)

    return {
        "message": "PASSWORD_RESET",
        "temporaryPassword": temp_password
    }

# Register new admin


@app.route('/register-new-admin', methods=['POST'])
def register_new_admin():
    registerant_info = request.get_json()
    if users.find_one({"username": registerant_info["username"]}):
        return "USERNAME_ALREADY_REGISTERED"

    # how to edit .env variable?
    if registerant_info["registrationCode"] in ENV_ADMIN_CODES:
        del (registerant_info["registrationCode"])
        del (registerant_info["class"])
        registerant_info["public_id"] = str(uuid.uuid4())
        registerant_info["username"] = registerant_info["username"].strip(
        ).lower()
        registerant_info["first"] = registerant_info["first"].strip().title()
        registerant_info["last"] = registerant_info["last"].strip().title()
        password = registerant_info["password"]
        registerant_info["passwordReset"] = False
        _hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=16)
        registerant_info["password"] = _hashed_password
        registerant_info["userRole"] = 'Administrator'

        users.insert_one(registerant_info)
        return "ADMINISTRATOR_REGISTERED"
    else:
        return "ADMINISTRATOR_REGISTRATION_FAILED"

# Lookup a user


@app.route('/lookup-user/<public_id>', methods=['GET'])
@jwt_required(fresh=True)
def lookup_user(public_id):
    user = users.find_one({"public_id": public_id})
    if user == None:
        return 'USER_NOT_FOUND'

    else:
        user["_id"] = str(user["_id"])

        return Response(
            response=json.dumps(user),
            status=200,
            mimetype="application/json"
        )

# Delete a user


@app.route('/delete-a-user/<public_id>', methods=['DELETE'])
@jwt_required(fresh=True)
def delete_a_user(public_id):
    user = users.find_one({"public_id": public_id})
    if user["userRole"] == "Student":
        classes.find_one_and_update(
            {"class": user["class"]}, {
                "$pull": {"classMembersList": user["public_id"]}}
        )
        classes.find_one_and_update({"class": user["class"]}, {"$inc": {
            "numberOfStudents": -1
        }})

    if user["userRole"] == "Administrator":
        if users.count_documents({"userRole": "Administrator"}) == 1:
            return 'LAST_ADMIN'

    users.delete_one({"public_id": public_id})

    return 'USER_DELETED'

# DELETE ALL USERS - A-BOMB


@app.route('/delete-all-users', methods=['DELETE'])
@jwt_required(fresh=True)
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
    if books.count_documents({'upc': UPC}, limit=1):
        book_info = books.find_one({"upc": UPC})
        book_info["_id"] = str(book_info["_id"])
        book_info["checkOutDate"] = str(book_info["checkOutDate"])
    # held_by = books.find_one({ "currentHolder" : {"$exists" : "true"}}) <--unnecessary? Just include current holder in book object and return that

        return Response(
            response=json.dumps(book_info),
            status=200,
            mimetype="application/json"
        )

    return 'Book not registered'

# Retrieve list of all registered publishers


@app.route('/retrieve-registered-publishers', methods=['GET'])
@cross_origin(True)
def retrieve_registered_publishers():
    list_of_publishers = []
    all_books = books.distinct("publisher")

    for publisher in all_books:
        list_of_publishers.append(publisher)

    return list_of_publishers

# Retrieve all currently checked out books and their holders


@app.route('/retrieve-all-checked-out-books', methods=['GET'])
@jwt_required(fresh=True)
def retrieve_all_checked_out_books():
    list_of_checked_out_books = books.find(
        {"currentHolder": {"$ne": "Onomichi Gakuen English Library"}})
    _list = []

    for book in list_of_checked_out_books:
        book["_id"] = str(book["_id"])
        today = datetime.datetime.now()
        check_out_date = book["checkOutDate"]
        book["totalDaysCheckedOut"] = (today - check_out_date).days + 1
        _list.append(book)

    return _list

# Retrieve book title(s) from list for a set of UPCs


@app.route('/retrieve-checked-out-books', methods=['POST'])
def retrieve_checked_out_books():
    list_of_UPCs = request.get_json()
    title_list = []

    for UPC in list_of_UPCs["checkedOutBooks"]:
        book_info = books.find_one({"upc": UPC})
        book_info["_id"] = str(book_info["_id"])
        title_list.append(book_info)

    return title_list

# Retrieve books with options


@app.route('/retrieve-books', methods=['POST'])
def retrieve_books_with_options():
    params = request.get_json()
    results = books.find(
        {'currentHolder': params['public_id']}, params['options'])

    return results

# Register or patch new book


@app.route('/register-new-book/<UPC>', methods=['POST', 'PUT'])
@jwt_required(fresh=True)
def register_new_book(UPC):

    if books.find_one({"upc": UPC}):
        return "BOOK_ALREADY_REGISTERED"

    new_book_info = request.get_json()
    new_book_info['title'] = new_book_info['title'].title()
    new_book_info['wordCount'] = int(new_book_info['wordCount'])

    books.insert_one(new_book_info)

    return f'BOOK_REGISTERED'

# Check book back in - #TODO - UGLY ass code here...


@app.route('/check-book-in', methods=['POST'])
@jwt_required(fresh=True)
def check_book_in():
    student_and_book_UPC = request.get_json()
    student = student_and_book_UPC["studentAndBookUPC"]["student"]
    UPC = student_and_book_UPC["studentAndBookUPC"]["book"]
    book = books.find_one({'upc': UPC})
    wordCount = book["wordCount"]
    books.update_one({'upc': UPC}, {"$set": {
        "status": "Checked in",
        "currentHolder": "Onomichi Gakuen English Library",
        "checkOutDate": None}})
    books.update_one({'upc': UPC}, {"$unset": {
        "totalDaysCheckedOut": ""
    }})
    users.update_one({'public_id': student}, {"$pull": {
        "checkedOutBooks": UPC
    }})
    student_read_book_list = users.find_one(
        {'public_id': student})["listOfReadBooks"]

    if UPC not in student_read_book_list:
        users.update_one({'public_id': student}, {"$inc": {
            "totalBooksRead": 1,
            "wordsRead": wordCount
        }})
        users.update_one({'public_id': student}, {"$push": {
            "listOfReadBooks": UPC
        }})
        student = users.find_one({'public_id': student})
        classes.update_one({"class": student["class"]}, {"$inc": {
            "classWordsRead": wordCount,
            "classTotalBooksRead": 1
        }})

    if UPC in student_read_book_list:
        users.update_one({'public_id': student}, {"$inc": {
            "wordsRead": wordCount
        }})
        student = users.find_one({'public_id': student})
        classes.update_one({"class": student["class"]}, {"$inc": {
            "classWordsRead": wordCount
        }})

    return f'{book["title"]} checked back in from {student["first"]} {student["last"]} - returning to Admin home'

# Check book out to student - #TODO


@app.route('/check-book-out', methods=['POST'])
@jwt_required(fresh=True)
def check_book_out():
    public_id_and_book_upc = request.get_json()
    public_id = public_id_and_book_upc["public_id"]
    book_upc = public_id_and_book_upc["book_upc"]
    student = users.find_one({'public_id': public_id})
    book = books.find_one({'upc': book_upc})

    users.find_one_and_update({'public_id': public_id}, {
                              "$push": {"checkedOutBooks": book_upc}})

    books.update_one({'upc': book_upc}, {"$set": {
        "status": "Checked Out",
        "currentHolder": student["public_id"],
        "checkOutDate": datetime.datetime.now()
    }})

    return f"{book['title']} checked out to {student['first']} {student['last']}"

# Delete a book


@app.route('/delete-a-book/<UPC>', methods=['DELETE'])
@jwt_required(fresh=True)
def delete_a_book(UPC):
    book_to_delete = books.find_one({'upc': UPC})
    delete_book = books.find_one_and_delete({'upc': UPC})

    return f'{book_to_delete["title"]} removed from database'

# Lookup individual class info


@app.route('/get-class-info', methods=['POST'])
@jwt_required(fresh=True)
def get_class_info():
    requested_class = request.get_json()
    _class = classes.find_one(requested_class)
    _class["_id"] = str(_class["_id"])

    return _class

# Return all class info as list of dicts


@app.route('/get-all-classes-info', methods=['GET'])
@jwt_required()
def get_all_classes_info():
    all_classes_info = classes.find()
    all_classes = []
    for _class in all_classes_info:
        _class["_id"] = str(_class["_id"])
        all_classes.append(_class)

    return all_classes

# Update a class


@app.route('/update-class', methods=['POST'])
@jwt_required(fresh=True)
def update_class():
    class_info = request.get_json()  # take in { "public_id" : public_id }
    classes.find_one_and_update({
        "public_id": class_info["public_id"]},
        {"$set": {"class": class_info["class"]}},
        return_document=pymongo.ReturnDocument.AFTER)

    return f'Class name updated to {class_info["class"]}'

# Delete a class


@app.route('/delete-class/<_class>', methods=['DELETE'])
@jwt_required(fresh=True)
def delete_a_class(_class):
    users.update_many({"class": _class},
                      {"$set": {"class": ""}})
    classes.find_one_and_delete({"class": _class})

    return "CLASS_DELETED"

# Return all administrators as array


@app.route('/get-all-administrators', methods=['GET'])
@jwt_required(fresh=True)
def get_all_administrators():
    administrators = users.find({"userRole": "Administrator"})
    admin = []

    for administrator in administrators:
        administrator["_id"] = str(administrator["_id"])
        admin.append(administrator)

    return make_response(admin, 200)

# Get Reader Leaders


@app.route('/get-reader-leaders', methods=['POST'])
def get_reader_leaders():
    reader_leader_request = request.get_json()  # just include class in request
    top_three = users.find(reader_leader_request).sort(
        "wordsRead", pymongo.DESCENDING).limit(3)
    _top_three = []
    for student in top_three:
        student["_id"] = str(student["_id"])
        _top_three.append(student)
    return _top_three


if __name__ == "__main__":
    app.run(debug=True)
