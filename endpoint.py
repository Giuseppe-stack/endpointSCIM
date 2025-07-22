from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token segreto condiviso con Entra ID
VALID_BEARER_TOKEN = "Bearer supersegreto"

# Utenti e gruppi in memoria (demo)
users = {}
groups = {}

# ✅ Middleware per autenticazione, ma esclude ServiceProviderConfig
@app.before_request
def check_auth():
    if request.path == '/scim/v2/ServiceProviderConfig':
        return  # Entra lo chiama senza token
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != VALID_BEARER_TOKEN:
        abort(401, description="Unauthorized: Invalid or missing Bearer token")

# 🔧 SCIM Service Provider Configuration
@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
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
    return jsonify(user), 201

# 🔁 Lista utenti
@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
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
    group_id = data.get('id', f"group-{len(groups)+1}")
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    return jsonify(group), 201

# 🔁 Lista gruppi
@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# 🧽 Eliminazione gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        return '', 204
    else:
        abort(404, description="Group not found")

# 🧠 Avvio app
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
