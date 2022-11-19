import json
import requests
from flask import jsonify
import datetime
from flask_jwt_extended import create_access_token, verify_jwt_in_request


class ControladorSeguridad():


    def __init__(self):
        print(" >Creando Controlador seguridad")
        self.dataConfig =self.loadFileConfig()
        

    def login(self,data):
        print("> Login: " + str(data))
        #logica verificacion Usuario
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url=self.dataConfig["url-backend-seguridad"]+'/usuarios/validate'
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            user = response.json()
            expires = datetime.timedelta(seconds=60 * 60*24)
            access_token = create_access_token(identity=user,expires_delta=expires)
            return jsonify({"token": access_token, "user_id": user["_id"]})
        else:
            return jsonify({"msg": "Bad username or password"}), 401
    
    def loadFileConfig(self):
        with open ('config.json') as f:
            data = json.load(f)
        return data     

  
  
