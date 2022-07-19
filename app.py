import os
import pymongo
# from bson.objectid import ObjectId
# from bson import json_util
from dotenv import find_dotenv, load_dotenv
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from flask import Flask, jsonify, make_response, Response, request
from flask_cors import CORS
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

# load_dotenv(find_dotenv())

CONNECTION_URL = 'mongodb+srv://JapanCodeMan:Le{m#u;W7uxB@cluster0.b1d3f.mongodb.net/?retryWrites=true&w=majority'
SECRET_KEY = 'lFNyAOBlNcTRKAKxfGg5'


client = pymongo.MongoClient("mongodb+srv://JapanCodeMan:<password>@cluster0.b1d3f.mongodb.net/?retryWrites=true&w=majority")

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

@app.route('/')
def test():
  return html

if __name__ == '__main__':
  app.run(debug=True) 