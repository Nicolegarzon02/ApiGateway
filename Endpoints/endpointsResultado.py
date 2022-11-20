from flask import jsonify, request, Blueprint
from Controladores.controladorResultado import ControladorResultado


controladorResultado = ControladorResultado()

endpointResultado = Blueprint("endpointsResultado", __name__ )


@endpointResultado.route("/resultado",methods=['GET'])
def listar_resultados():
    response = controladorResultado.index()
    print(response)
    return jsonify(response) if not isinstance(response,tuple) else (jsonify(response[0]), response[1])
    