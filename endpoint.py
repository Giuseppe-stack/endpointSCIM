from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token segreto condiviso con Entra ID
VALID_BEARER_TOKEN = "supersegreto"

# Utenti e gruppi in memoria (demo)
users = {}
groups = {}

# ✅ Middleware per autenticazione, esclude ServiceProviderConfig
@app.before_request
def check_auth():
    if request.path == '/scim/v2/ServiceProviderConfig':
        print(f"[{request.method}] {request.path} - accesso senza token")
        return  # Entra lo chiama senza token
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f"Bearer {VALID_BEARER_TOKEN}":
        print(f"[{request.method}] {request.path} - Unauthorized: Missing or invalid token")
        abort(401, description="Unauthorized: Invalid or missing Bearer token")
    print(f"[{request.method}] {request.path} - Authorized")

# 🔧 SCIM Service Provider Configuration
@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    print("[GET] /scim/v2/ServiceProviderConfig")
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

# 📩 Creazione utente (da Entra)
@app.route('/scim/v2/Users', methods=['POST'])
def create_user():
    data = request.get_json()
    print("[POST] /scim/v2/Users - Payload ricevuto:", data)
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
    print(f"Utente creato: {user_id}")
    return jsonify(user), 201

# 🔁 Lista utenti
@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    print("[GET] /scim/v2/Users - Lista utenti richiesta")
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# 📩 Creazione gruppo
@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    print("[POST] /scim/v2/Groups - Payload ricevuto:", data)
    group_id = data.get('id', f"group-{len(groups)+1}")
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    print(f"Gruppo creato: {group_id}")
    return jsonify(group), 201

# 🔁 Lista gruppi
@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    print("[GET] /scim/v2/Groups - Lista gruppi richiesta")
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# 🖊️ Aggiornamento gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['PUT'])
def update_group(group_id):
    data = request.get_json()
    print(f"[PUT] /scim/v2/Groups/{group_id} - Payload ricevuto:", data)
    if group_id not in groups:
        print(f"Gruppo {group_id} non trovato")
        abort(404, description="Group not found")
    groups[group_id] = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    print(f"✅ Gruppo aggiornato: {group_id}")
    return jsonify(groups[group_id])

# 🧽 Eliminazione gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    print(f"[DELETE] /scim/v2/Groups/{group_id} - Richiesta eliminazione")
    if group_id in groups:
        del groups[group_id]
        print(f"Gruppo eliminato: {group_id}")
        return '', 204
    else:
        print(f"Gruppo {group_id} non trovato")
        abort(404, description="Group not found")

# 🧠 Avvio app
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Server avviato sulla porta {port}")
    app.run(host='0.0.0.0', port=port)
