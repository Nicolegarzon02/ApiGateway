from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import json
from waitress import serve
import datetime
import requests
import re
import Endpoints
app=Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que seconveniente
jwt = JWTManager(app)
app.register_blueprint(Endpoints.endpointSeguridad)

def loadFileConfig():
    with open ('config.json') as f:
        data = json.load(f)
    return data 

@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)

if __name__=='__main__':
     dataConfig = loadFileConfig()
     print("Server running : "+"http://"+dataConfig["url-backend"]+":" +
str(dataConfig["port"]))
     serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])