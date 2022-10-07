from flask import Flask, jsonify, request
from flask import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongo://db:27017")

db = client.SimilarityDB

users = db["Users"]


def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


def verify_password(username, password):
    if not UserExist(username):
        return False
    hashed_password = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_password) == hashed_password:
        return True
    else:
        return False


def count_tokens(username):
    tokens = users.find({"Username": username})[0]["Tokens"]
    return tokens


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        # 1. check if user exist
        if UserExist(username):
            retJson = {'status': 301, "message": "username already exist"}
            return jsonify(retJson)

        # 2 has password, save user with hashed password and Tokens  = 6
        hashed_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert_one({"Username": username, "Password": hashed_password, "Tokens": 6})

        # Give response
        retJson = {"status": 200, "message": "You have successfully signed up for NLP API"}


class Detect(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        # verify user
        if not UserExist(username):
            retJson = {'status': 301, "message": "invalid username"}
            return jsonify(retJson)

        # Verify password
        correct_password = verify_password(username, password)
        if not correct_password:
            retJson = {"status": 302, "message": "Invalid Password"}
            return jsonify(retJson)

        # check tokens
        num_tokens = count_tokens(username)
        if num_tokens <= 0:
            retJson = {"status": 303, "message": "You are out of Tokens", "Tokens": num_tokens}
            return jsonify(retJson)

        # calculate the edit distance

        nlp = spacy.load("en_core_web_sm")
        text1 = nlp(text1)
        text2 = nlp(text2)

        # Check Plagiarism
        # Ratio btn 0-1, the closer to 1 the more similar the texts[text1 & text 2] are
        ratio = text1.similarity(text2)

        # check tokens
        current_tokens = count_tokens(username)

        # Update user's number of tokens
        users.update_one({
            "Username": username
        }, {"$set": {"Tokens": current_tokens - 1}})

        # send response
        retJson = {
            "status": 200,
            "similarity": ratio,
            "Tokens": current_tokens,
            "message": "Similarity scored successfully calculated"}
        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        # Get the data
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["admin_password"]
        refill_amount = postedData["refill"]

        # Check invalid username
        if not UserExist(username):
            retJson = {'status': 301, "message": "invalid username"}
            return jsonify(retJson)

        # Invalid admin password
        admin_password = "admin123"
        if not password == admin_password:
            retJson = {'status': 304, "message": "invalid admin password"}
            return jsonify(retJson)

        # check validity of token [<=0  or a string ]
        if refill_amount <= 0 or refill_amount != int:
            retJson = {'status': 305, "message": "invalid refill amount"}
            return jsonify(retJson)

        # Update user tokens
        users.update_one({
            "Username": username
        }, {"$set": {"Tokens": refill_amount}})

        retJson = {"status": 200, "message": "token refill successful", "username": username, "Tokens": refill_amount}
        return jsonify(retJson)


api.add_resource(Register, "/register")
api.add_resource(Refill, "/refill")
api.add_resource(Detect, "/detect")

if __name__ == '__main__':
    app.run(host='0.0.0.0')
