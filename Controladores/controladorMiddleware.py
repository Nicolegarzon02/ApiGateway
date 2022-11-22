import json
import requests
import re
from flask import jsonify , request
from flask_jwt_extended import  verify_jwt_in_request,get_jwt_identity


class ControladorMiddleware():


    def __init__(self):
        print(" >Creando Controlador middleware")
        self.dataConfig =self.loadFileConfig()

    def after_request_func(self,response ):
        print("\t\t>>AFTER")
        return response

    def limpiarURL(self,url):
        partes = request.path.split("/")
        for laParte in partes:
            if re.search('\\d', laParte):
                url = url.replace(laParte, "?")
        return url

    def validarPermiso(self,endPoint,metodo,idRol):
        url=self.dataConfig["url-backend-seguridad"]+"/permisos-roles/validarpermiso/rol/"+str(idRol)
        tienePermiso=False
        headers = {"Content-Type": "application/json; charset=utf-8"}
        body={
            "url":endPoint,
            "metodo":metodo
        }
        response = requests.get(url,json=body, headers=headers)
        try:
            data=response.json()
            if("_id" in data):
                tienePermiso=True
        except:
            pass
        return tienePermiso

    def before_request_callback(self):
        print("\t\t>>BEFORE")
        endPoint=self.limpiarURL(request.path)
        excludedRoutes=["/","/login"]
        if excludedRoutes.__contains__(request.path):
            print("ruta excluida ",request.path)
            pass
        elif verify_jwt_in_request():
            usuario = get_jwt_identity()
            if usuario["rol"]is not None:
                tienePersmiso=self.validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
                if not tienePersmiso:
                    return jsonify({"message": "Permission denied"}), 401
            else:
                return jsonify({"message": "Permission denied"}), 403

    def loadFileConfig(self):
        with open ('config.json') as f:
            data = json.load(f)
        return data