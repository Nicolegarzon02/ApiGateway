from flask import jsonify, request, Blueprint
from Controladores.controladorSeguridad import ControladorSeguridad


controladorSeguridad = ControladorSeguridad()

endpointSeguridad = Blueprint("endpointsSeguridad", __name__ )


@endpointSeguridad.route("/login",methods=['POST'])
def login():
    data = request.get_json()
    response = controladorSeguridad.login(data)
    return response

