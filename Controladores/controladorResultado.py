import json
import requests
from flask import jsonify




class ControladorResultado():


    def __init__(self):
        print(" >Creando Controlador resultado")
        self.dataConfig =self.loadFileConfig()
        

    def index(self):
        print("> Resultado index")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url=self.dataConfig["url-backend-resultados"]+'/resultado'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json = response.json()
            print(json)
            return json
        else:
            return jsonify({"msg": "Error ms resultados"}), 500
    
    def loadFileConfig(self):
        with open ('config.json') as f:
            data = json.load(f)
        return data     

  
  
