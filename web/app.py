from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import requests
import subprocess
import json
import time
import os
import tensorflow
import keras
from PIL import Image
import numpy as np
from keras.models import load_model
from flask_cors import CORS

app = Flask(__name__)

api = Api(app)
#api = CORS(app)

client = MongoClient("mongodb://db:27017")

db = client.ImageRecognition

users = db["Users"]

model = load_model("modelv3.6.h5")

def userExist(username):
    if (users.find({"username":username}).count() == 0):
        return jsonify({
            "status": 301,
            "msg": "This user does not exist."
        })
    else:
        return 200

def verifyPw(username, password):
    userCheck = userExist(username)
    if userExist != 200:
        return userCheck

    hashedPw = users.find({"username":username})[0]["password"]

    if(bcrypt.hashpw(password.encode("utf8"), hashedPw) == hashedPw):
        return 200
    else:
        return jsonify({
            "status": 301,
            "msg": "Invalid password"
        })

def generateResponse(errorCode, message):
    return jsonify({
        "status": errorCode,
        "msg": message
    })

class Register(Resource):
    def post(self):
        postedData = request.get_json()
        requestCheck = self.checkRequest(postedData)

        if(requestCheck == 200):
            username = postedData["username"]
            password = postedData["password"]
        else:
            return requestCheck

        userCheck = userExist(username)
        if(userCheck != 200):
            hashedPw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
            users.insert({
                "username": username,
                "password": hashedPw,
                "tokens": 4
            })
        else:
            return generateResponse(305, "Username is taken.")
        
        return jsonify({
            "status": 200,
            "msg": "Successfuly registered to the Api. You have 4 tokens."
        })
            
    def checkRequest(self, postedData):
        if("username" in postedData and "password" in postedData):
            return 200
        else:
            return jsonify({
                "status":301,
                "msg": "Username or Password is missing."
            })

class Classify(Resource):
    def post(self):
        postedData = request.get_json()
        requestCheck = self.checkRequest(postedData)

        if(requestCheck == 200):
            username = postedData["username"]
            password = postedData["password"]
            url = postedData["url"]
        else:
            return requestCheck

        passwordCheck = verifyPw(username, password)
        if(passwordCheck != 200):
            return passwordCheck
        
        tokens = users.find({
            "username":username,
        })[0]["tokens"]

        if tokens<=0:
            return generateResponse(303, "Not Enough Tokens")

        img = requests.get(url)
        retJson = {}
        with open("temp.jpg", "wb") as f:
            f.write(img.content)

        proc = subprocess.Popen(["python3 classify.py --model_dir=. --image-file=temp.jpg"], shell=True)
        out, err = proc.communicate()
        proc.wait()
        r=proc.returncode

        try:
            with open("text.txt", "r") as g:
                retJson = json.load(g)
            os.remove("./text.txt")
            os.remove("./temp.jpg")
        except:
            return jsonify({
                "out": out,
                "error": err
            })
    
        users.update(
            {"username":username},
            {"$set":{"tokens": tokens-1}}
        )

        return retJson

    def checkRequest(self, postedData):
        if(not ("username" in postedData and "password" in postedData)):
            return jsonify({
                "status":301,
                "msg": "Username or Password is missing."
            })
        elif(not "url" in postedData):
            return jsonify({
                "status":302,
                "msg": "Image url is missing."
            })
        else:
            return 200

class Refill(Resource):
    def post(self):
        correctAdminPw = "asdqwe"
        postedData = request.get_json()
        requestCheck = self.checkRequest(postedData)
        if(requestCheck == 200):
            username = postedData["username"]
            password = postedData["adminPw"]
            tokenAmount = postedData["amount"]
        else:
            return requestCheck
        
        userCheck = userExist(username)
        if(userCheck != 200):
            return userCheck

        if(password != correctAdminPw):
            return generateResponse(304, "Invalid admin password.") 
        
        users.update(
            {"username":username},
            {"$set":{"token": tokenAmount}}    
        )

        return generateResponse(200, "Tokens are refilled successfuly.")

    def checkRequest(self, postedData):
        if(not ("username" in postedData and "adminPw" in postedData)):
            return generateResponse(301, "Username or password is missing.")
        elif(not "amount" in postedData):
            return generateResponse(302, "Token amount is missing.")
        else:
            return 200

class Classify2(Resource):
    def post(self):
        img = Image.open(request.files['image']).resize((224,224),0)
        img = np.array(img).reshape(1,224,224,3)
        pred = model.predict(img).argmax()
        prediction = ["Adult", "Normal", "Violence"][pred]
        # prediction = "Adult" if  pred == 0 else ("Normal" if pred == 1 else "Violence") 
        return jsonify({
            "files": prediction
        })

api.add_resource(Register, "/Register")
api.add_resource(Classify, "/Classify")
api.add_resource(Refill, "/refill")
api.add_resource(Classify2, "/classify")

if __name__ == "__main__":
    app.run(host="0.0.0.0")