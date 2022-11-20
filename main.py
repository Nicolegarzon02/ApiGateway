from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import json
from waitress import serve
import datetime
import requests

import Endpoints
from Controladores.controladorMiddleware import ControladorMiddleware

app=Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que seconveniente
jwt = JWTManager(app)

app.register_blueprint(Endpoints.endpointResultado)
app.register_blueprint(Endpoints.endpointSeguridad)

middleware = ControladorMiddleware()

def loadFileConfig():
    with open ('config.json') as f:
        data = json.load(f)
    return data 

@app.before_request
def before_request_f ():
    middleware.before_request_func()    

@app.after_request
def after_request_f (response):
    r=middleware.after_request_func(response)
    return r   

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