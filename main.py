import re
from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request
import json
from waitress import serve
import datetime
import requests

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

@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        print("ruta excluida ",request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def limpiarURL(url):
    partes = request.path.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-seguridad"]+"/permisos-roles/validarpermiso/rol/"+str(idRol)
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
    
########## RUTAS RESULTADO######

@app.route("/resultado",methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/resultado'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado",methods=['POST'])
def crearResultado(self):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/resultado'
        response = requests.post(url, headers=headers,json=data)
        json = response.json()
        return jsonify(json)

@app.route("/resultado/<string:id>",methods=['GET'])
def getResultado(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/resultado/'+id
        response = requests.get(url, headers=headers)
        json = response.json()
        return jsonify(json)

@app.route("/resultado/<string:id>",methods=['PUT'])
def modificarResultado(id):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/resultado/'+id
        response = requests.put(url, headers=headers, json=data)
        json = response.json()
        return jsonify(json)

@app.route("/resultado/<string:id>",methods=['DELETE'])
def eliminarResultado(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/resultado/' + id
        response = requests.delete(url, headers=headers)
        json = response.json()
        return jsonify(json)
##### FIN RUTAS RESULTADO#######


########## RUTAS PARTIDO ######

@app.route("/partido",methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/partido'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partido",methods=['POST'])
def crearPartido(self):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/partido'
        response = requests.post(url, headers=headers,json=data)
        json = response.json()
        return jsonify(json)

@app.route("/partido/<string:id>",methods=['GET'])
def getPartido(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/partido/'+id
        response = requests.get(url, headers=headers)
        json = response.json()
        return jsonify(json)

@app.route("/partido/<string:id>",methods=['PUT'])
def modificarPartido(id):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/partido/'+id
        response = requests.put(url, headers=headers, json=data)
        json = response.json()
        return jsonify(json)

@app.route("/partido/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/partido/' + id
        response = requests.delete(url, headers=headers)
        json = response.json()
        return jsonify(json)
##### FIN RUTAS PARTIDO #######

################################
@app.route("/candidato",methods=["GET"])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/candidato'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidato",methods=["POST"])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/candidato"
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>",methods=["GET"])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/candidato/" +id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>",methods=["PUT"])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/candidato/" +id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>",methods=["DELETE"])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/candidato/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################################
######### Ruta Rol #############
@app.route("/rol",methods=["GET"])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/rol'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/rol",methods=["POST"])
def crearRol():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/rol"
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/rol/<string:id>",methods=["GET"])
def getRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/rol/" +id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/rol/<string:id>",methods=["PUT"])
def modificarRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/rol/" +id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/rol/<string:id>",methods=["DELETE"])
def eliminarRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/rol/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


##################################
@app.route("/mesa",methods=["GET"])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/mesa'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa",methods=["POST"])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/mesa"
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id>",methods=["GET"])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/mesa/" +id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id>",methods=["PUT"])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/mesa/" +id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id>",methods=["DELETE"])
def eliminarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + "/mesa/" + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
################################
  
############## RUTA PERMISOS -ROLES ####################

@app.route("/permisos-roles",methods=['GET'])
def getPermisoRol():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/permisos-roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles",methods=['POST'])
def crearPermisorol(self):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos-roles'
        response = requests.post(url, headers=headers,json=data)
        json = response.json()
        return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['GET'])
def getPermisorol(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos-roles/'+id
        response = requests.get(url, headers=headers)
        json = response.json()
        return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['PUT'])
def modificarPermisorol(id):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos-roles/'+id
        response = requests.put(url, headers=headers, json=data)
        json = response.json()
        return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['DELETE'])     
def eliminarPermisoRol(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos-roles/' + id
        response = requests.delete(url, headers=headers)
        json = response.json()
        return jsonify(json)
    
######################################################


########## RUTAS USUARIOS ######


@app.route("/usuarios",methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios",methods=['POST'])
def crearUsuarios(self):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/usuarios'
        response = requests.post(url, headers=headers,json=data)
        json = response.json()
        return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['GET'])
def getUsuario(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/usuarios/'+id
        response = requests.get(url, headers=headers)
        json = response.json()
        return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['PUT'])
def modificarUsuarios(id):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/usuarios/'+id
        response = requests.put(url, headers=headers, json=data)
        json = response.json()
        return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['DELETE'])
def eliminarUsuario(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/usuarios/' + id
        response = requests.delete(url, headers=headers)
        json = response.json()
        return jsonify(json)
##### FIN RUTAS USUARIO #######

########## BACKEND SEGURIDAD ######

########## RUTAS PERMISOS ######


@app.route("/permisos",methods=['GET'])
def getPermisos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios",methods=['POST'])
def crearPermisos(self):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos'
        response = requests.post(url, headers=headers,json=data)
        json = response.json()
        return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['GET'])
def getPermisos(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos/'+id
        response = requests.get(url, headers=headers)
        json = response.json()
        return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['PUT'])
def modificarPermisos(id):
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos/'+id
        response = requests.put(url, headers=headers, json=data)
        json = response.json()
        return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['DELETE'])
def eliminarPermisos(id):
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-seguridad"] + '/permisos/' + id
        response = requests.delete(url, headers=headers)
        json = response.json()
        return jsonify(json)
##### FIN RUTAS PERMISOS #######


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