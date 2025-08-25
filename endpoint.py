import os
import uuid
from flask import Flask, request, jsonify, abort
from functools import wraps

app = Flask(__name__)

# In-memory storage per demo (in produzione usa DB)
users = {}
groups = {}

VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer"):
            abort(401, description="Missing Bearer token")
        token = auth_header.replace("Bearer", "").strip()
        if token != VALID_TOKEN:
            abort(401, description="Invalid Bearer token")
        return f(*args, **kwargs)
    return decorated

def generate_id(prefix):
    return f"{prefix}_{str(uuid.uuid4())}"

# ----------- USERS ------------

@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.get_json()
    userName = data.get("userName")
    if not userName:
        abort(400, description="userName is required")

    # Evita duplicati
    existing = next((u for u in users.values() if u["userName"] == userName), None)
    if existing:
        return jsonify(existing), 200

    user_id = data.get("id") or str(uuid.uuid4())

    user = {
        "id": user_id,
        "userName": userName,
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "title": data.get("title"),
        "emails": data.get("emails", []),
        "preferredLanguage": data.get("preferredLanguage"),
        "name": data.get("name", {
            "givenName": None,
            "familyName": None,
            "formatted": None
        }),
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "employeeNumber": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"),
        "department": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"),
        "manager": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager"),
        "schemas": data.get("schemas", [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ]),
    }

    users[user_id] = user
    return jsonify(user), 201

@app.route("/scim/v2/Users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    return jsonify(user)

@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route("/scim/v2/Users/<user_id>", methods=["PUT"])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json()
    userName = data.get("userName")
    if not userName:
        abort(400, description="userName is required")

    user = {
        "id": user_id,
        "userName": userName,
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "title": data.get("title"),
        "emails": data.get("emails", []),
        "preferredLanguage": data.get("preferredLanguage"),
        "name": data.get("name", {
            "givenName": None,
            "familyName": None,
            "formatted": None
        }),
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "employeeNumber": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"),
        "department": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"),
        "manager": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager"),
        "schemas": data.get("schemas", [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ]),
    }
    users[user_id] = user
    return jsonify(user)

@app.route("/scim/v2/Users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    # Rimuovi user da tutti i gruppi
    for group in groups.values():
        group["members"] = [m for m in group.get("members", []) if m["value"] != user_id]
    del users[user_id]
    return '', 204

# ----------- GROUPS ------------

@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.get_json()
    displayName = data.get("displayName")
    if not displayName:
        abort(400, description="displayName is required")

    existing = next((g for g in groups.values() if g["displayName"] == displayName), None)
    if existing:
        return jsonify(existing), 200

    group_id = data.get("id") or str(uuid.uuid4())

    members = data.get("members", [])  # es. [{"value": "user_id", "display": "name"}]

    group = {
        "id": group_id,
        "displayName": displayName,
        "members": members,
        "schemas": data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:Group"]),
    }

    groups[group_id] = group
    return jsonify(group), 201

@app.route("/scim/v2/Groups/<group_id>", methods=["GET"])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")
    return jsonify(group)

@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route("/scim/v2/Groups/<group_id>", methods=["PUT"])
@require_auth
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    data = request.get_json()
    displayName = data.get("displayName")
    if not displayName:
        abort(400, description="displayName is required")

    members = data.get("members", [])

    group = {
        "id": group_id,
        "displayName": displayName,
        "members": members,
        "schemas": data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:Group"]),
    }

    groups[group_id] = group
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["DELETE"])
@require_auth
def delete_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    del groups[group_id]
    return '', 204

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
