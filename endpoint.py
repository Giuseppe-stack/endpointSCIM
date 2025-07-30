from flask import Flask, request, jsonify, abort
from functools import wraps
import os
import uuid
import json

app = Flask(__name__)

VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")

USERS_FILE = "users.json"
GROUPS_FILE = "groups.json"

# Funzioni di persistenza su file
def load_data(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

users = load_data(USERS_FILE)
groups = load_data(GROUPS_FILE)

# Autenticazione Bearer
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.path in ["/", "/favicon.ico", "/scim/v2/ServiceProviderConfig"]:
            return f(*args, **kwargs)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer"):
            abort(401, description="Missing Bearer token")
        token = auth_header.replace("Bearer", "").strip()
        if token != VALID_TOKEN:
            abort(401, description="Invalid Bearer token")
        return f(*args, **kwargs)
    return decorated

# Config SCIM
@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
@require_auth
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

# ------------------------- USERS -------------------------

@app.route('/scim/v2/Users', methods=['POST'])
@require_auth
def create_user():
    data = request.get_json()
    for user in users.values():
        if user.get("userName") == data.get("userName"):
            return jsonify(user), 200
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "title": data.get("title"),
        "emails": data.get("emails", []),
        "preferredLanguage": data.get("preferredLanguage"),
        "name": data.get("name", {}),
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", []),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {})
    }
    users[user_id] = user
    save_data(USERS_FILE, users)
    return jsonify(user), 201

@app.route('/scim/v2/Users', methods=['GET'])
@require_auth
def list_users():
    filter_param = request.args.get('filter')
    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        matched = [u for u in users.values() if u.get("userName") == username]
        return jsonify({"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100, "startIndex": 1})
    return jsonify({"Resources": list(users.values()), "totalResults": len(users), "itemsPerPage": 100, "startIndex": 1})

@app.route('/scim/v2/Users/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if user:
        return jsonify(user)
    abort(404, description="User not found")

@app.route('/scim/v2/Users/<user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json()
    users[user_id].update(data)
    save_data(USERS_FILE, users)
    return jsonify(users[user_id])

@app.route('/scim/v2/Users/<user_id>', methods=['PATCH'])
@require_auth
def patch_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json()
    for op in data.get("Operations", []):
        path = op.get("path")
        value = op.get("value")
        if path and value:
            keys = path.split(".")
            ref = users[user_id]
            for key in keys[:-1]:
                ref = ref.setdefault(key, {})
            ref[keys[-1]] = value
    save_data(USERS_FILE, users)
    return jsonify(users[user_id])

@app.route('/scim/v2/Users/<user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        save_data(USERS_FILE, users)
        return '', 204
    abort(404, description="User not found")

# ------------------------- GROUPS -------------------------

@app.route('/scim/v2/Groups', methods=['POST'])
@require_auth
def create_group():
    data = request.get_json()
    group_id = str(uuid.uuid4())
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    save_data(GROUPS_FILE, groups)
    return jsonify(group), 201

@app.route('/scim/v2/Groups', methods=['GET'])
@require_auth
def list_groups():
    return jsonify({"Resources": list(groups.values()), "totalResults": len(groups), "itemsPerPage": 100, "startIndex": 1})

@app.route('/scim/v2/Groups/<group_id>', methods=['GET'])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if group:
        return jsonify(group)
    abort(404, description="Group not found")

@app.route('/scim/v2/Groups/<group_id>', methods=['PUT'])
@require_auth
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    data = request.get_json()
    groups[group_id].update(data)
    save_data(GROUPS_FILE, groups)
    return jsonify(groups[group_id])

@app.route('/scim/v2/Groups/<group_id>', methods=['PATCH'])
@require_auth
def patch_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    data = request.get_json()
    for op in data.get("Operations", []):
        path = op.get("path")
        value = op.get("value")
        if path and value:
            keys = path.split(".")
            ref = groups[group_id]
            for key in keys[:-1]:
                ref = ref.setdefault(key, {})
            ref[keys[-1]] = value
    save_data(GROUPS_FILE, groups)
    return jsonify(groups[group_id])

@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        save_data(GROUPS_FILE, groups)
        return '', 204
    abort(404, description="Group not found")

# ------------------------- ROOT -------------------------

@app.route('/')
@app.route('/favicon.ico')
def root():
    return "SCIM endpoint OK", 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
