from flask import Flask, request, jsonify, abort
import base64
import os
import re

app = Flask(__name__)

# Credenziali accettate dal tuo SCIM server
VALID_USERNAME = "entra"
VALID_PASSWORD = "supersegreto"

# Middleware Basic Auth
@app.before_request
def check_auth():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        abort(401, description="Unauthorized: Missing Basic auth")

    try:
        base64_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':', 1)
    except Exception:
        abort(401, description="Unauthorized: Malformed credentials")

    if username != VALID_USERNAME or password != VALID_PASSWORD:
        abort(401, description="Unauthorized: Invalid credentials")

# Dati statici di esempio
users = {
    "user-1": {"id": "user-1", "userName": "alice@example.com", "groups": []},
    "user-2": {"id": "user-2", "userName": "bob@example.com", "groups": []}
}
groups = {}

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
            "type": "httpbasic",
            "name": "HTTP Basic",
            "description": "Basic authentication",
            "specUri": "http://www.rfc-editor.org/info/rfc7617"
        }]
    })

@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    filter_query = request.args.get('filter')
    filtered_users = list(users.values())

    if filter_query:
        match = re.match(r'userName eq "(.+)"', filter_query)
        if match:
            username = match.group(1)
            filtered_users = [u for u in users.values() if u["userName"] == username]

    return jsonify({
        "Resources": filtered_users,
        "totalResults": len(filtered_users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    group_id = data.get('id', f"group-{len(groups)+1}")
    groups[group_id] = data

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
            for user in users.values():
                if group_id in user['groups']:
                    user['groups'].remove(group_id)
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
