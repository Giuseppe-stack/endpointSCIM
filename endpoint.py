from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token usato da Entra ID
EXPECTED_BEARER_TOKEN = "supersegreto"  # Deve corrispondere a quanto inserisci nel campo Secret Token su Entra ID

# In-memory database simulato
users = {}
groups = {}

# 🔐 Middleware: verifica Bearer token in ogni richiesta
@app.before_request
def check_bearer_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        abort(401, description="Unauthorized: Missing Bearer token")
    
    token = auth_header.split(" ")[1]
    if token != EXPECTED_BEARER_TOKEN:
        abort(401, description="Unauthorized: Invalid Bearer token")

# 🔧 Configurazione del provider SCIM
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

# 👤 GET /Users – elenco utenti
@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# 👤 POST /Users – crea utente
@app.route('/scim/v2/Users', methods=['POST'])
def create_user():
    data = request.get_json()
    print("📥 Create User:", data)

    user_id = data.get("id") or f"user-{len(users)+1}"
    userName = data.get("userName")
    
    if not userName:
        return jsonify({"error": "Missing userName"}), 400

    user = {
        "id": user_id,
        "userName": userName,
        "name": data.get("name", {}),
        "emails": data.get("emails", []),
        "active": data.get("active", True),
        "groups": [],
        "externalId": data.get("externalId", "")
    }

    users[user_id] = user

    return jsonify(user), 201

# 👥 GET /Groups – elenco gruppi
@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# 👥 POST /Groups – crea un nuovo gruppo
@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    print("📥 Create Group:", data)

    group_id = data.get('id') or f"group-{len(groups)+1}"
    groups[group_id] = data

    for member in data.get('members', []):
        user_id = member.get('value')
        if user_id in users and group_id not in users[user_id]["groups"]:
            users[user_id]["groups"].append(group_id)

    return jsonify(data), 201

# 👥 PATCH /Groups/{id} – aggiorna membri di un gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['PATCH'])
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")

    patch_data = request.get_json()
    print("🔧 Patch Group:", patch_data)

    for op in patch_data.get('Operations', []):
        if op['op'].lower() == 'replace' and 'members' in op['value']:
            for user in users.values():
                if group_id in user['groups']:
                    user['groups'].remove(group_id)

            for member in op['value']['members']:
                user_id = member.get('value')
                if user_id in users and group_id not in users[user_id]["groups"]:
                    users[user_id]["groups"].append(group_id)

    return jsonify(groups[group_id])

# 👥 DELETE /Groups/{id} – elimina un gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    if group_id in groups:
        for user in users.values():
            if group_id in user['groups']:
                user['groups'].remove(group_id)
        del groups[group_id]
    return '', 204

# 🔁 Run
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
