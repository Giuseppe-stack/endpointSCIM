from flask import Flask, request, jsonify, abort

import os

app = Flask(__name__)

# Token segreto condiviso con Entra ID
VALID_BEARER_TOKEN = "Bearer inserisci-qui-il-tuo-token"

# Utenti statici predefiniti
users = {
    "user-1": {"id": "user-1", "userName": "alice@example.com", "groups": []},
    "user-2": {"id": "user-2", "userName": "bob@example.com", "groups": []}
}

# Gruppi ricevuti da Entra ID
groups = {}

# Middleware per autenticazione Bearer
@app.before_request
def check_auth():
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != VALID_BEARER_TOKEN:
        abort(401, description="Unauthorized: Invalid or missing Bearer token")

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
            "description": "SCIM Bearer Token",
            "specUri": "http://www.rfc-editor.org/info/rfc6750"
        }]
    })

@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    group_id = data.get('id', f"group-{len(groups)+1}")
    groups[group_id] = data

    # Assegna il gruppo agli utenti esistenti indicati nel payload
    for member in data.get('members', []):
        user_id = member.get('value')
        if user_id in users:
            if group_id not in users[user_id]['groups']:
                users[user_id]['groups'].append(group_id)

    return jsonify(data), 201

@app.route('/scim/v2/Groups/<group_id>', methods=['PATCH'])
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")

    patch_data = request.get_json()
    for op in patch_data.get('Operations', []):
        if op['op'].lower() == 'replace' and 'members' in op['value']:
            # Rimuove il gruppo da tutti gli utenti
            for user in users.values():
                if group_id in user['groups']:
                    user['groups'].remove(group_id)
            # Aggiunge il gruppo agli utenti indicati
            for member in op['value']['members']:
                user_id = member.get('value')
                if user_id in users:
                    if group_id not in users[user_id]['groups']:
                        users[user_id]['groups'].append(group_id)

    return jsonify(groups[group_id])

@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    if group_id in groups:
        for user in users.values():
            if group_id in user['groups']:
                user['groups'].remove(group_id)
        del groups[group_id]
    return '', 204

@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

