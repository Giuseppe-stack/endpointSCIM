from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token segreto senza prefisso Bearer
VALID_TOKEN = "supersegreto"

# Utenti e gruppi in memoria (demo)
users = {}
groups = {}

@app.before_request
def check_auth():
    # ServiceProviderConfig non richiede autenticazione
    if request.path == '/scim/v2/ServiceProviderConfig':
        print("[Auth] Accesso senza token a ServiceProviderConfig")
        return

    auth_header = request.headers.get('Authorization')
    print(f"[Auth] Authorization header: {auth_header}")

    if not auth_header or not auth_header.startswith("Bearer "):
        print("[Auth] Errore: header mancante o senza Bearer")
        abort(401, description="Unauthorized: Invalid or missing Bearer token")

    token = auth_header.split(" ")[1]
    print(f"[Auth] Token estratto: {token}")

    if token != VALID_TOKEN:
        print("[Auth] Errore: token non valido")
        abort(401, description="Unauthorized: Invalid Bearer token")

    print("[Auth] Autenticazione riuscita")

@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    print("[API] ServiceProviderConfig richiesta")
    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": True},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "SCIM Bearer Token Authentication",
            "specUri": "http://www.rfc-editor.org/info/rfc6750"
        }]
    })

@app.route('/scim/v2/Users', methods=['POST'])
def create_user():
    data = request.get_json()
    print(f"[API] Create user: {data}")
    user_id = data.get('id', data.get('externalId', f"user-{len(users)+1}"))
    user = {
        "id": user_id,
        "userName": data.get("userName"),
        "name": data.get("name", {}),
        "emails": data.get("emails", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", [])
    }
    users[user_id] = user
    print(f"[Data] Users attuali: {list(users.keys())}")
    return jsonify(user), 201

@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    print("[API] Lista utenti richiesta")
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    print(f"[API] Create group: {data}")
    group_id = data.get('id', f"group-{len(groups)+1}")
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    print(f"[Data] Groups attuali: {list(groups.keys())}")
    return jsonify(group), 201

@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    print("[API] Lista gruppi richiesta")
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    print(f"[API] Delete group: {group_id}")
    if group_id in groups:
        del groups[group_id]
        print(f"[Data] Group {group_id} eliminato")
        return '', 204
    else:
        print(f"[Error] Group {group_id} non trovato")
        abort(404, description="Group not found")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"Avvio app sulla porta {port}")
    app.run(host='0.0.0.0', port=port)
