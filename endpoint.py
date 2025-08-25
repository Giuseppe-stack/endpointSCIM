import os
import uuid
from flask import Flask, request, jsonify, abort
from functools import wraps

app = Flask(__name__)

# In-memory storage
users = {}
groups = {}

# Token di autenticazione
VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")

# Decoratore autenticazione
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

def generate_id(prefix):
    return f"{prefix}_{str(uuid.uuid4())}"

# --- USERS ---

def build_user(data, user_id):
    # Costruisce la struttura user senza groups (gruppi non sono passati dall'esterno)
    return {
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "title": data.get("title"),
        "emails": data.get("emails", []),
        "preferredLanguage": data.get("preferredLanguage"),
        "name": {
            "givenName": data.get("name", {}).get("givenName"),
            "familyName": data.get("name", {}).get("familyName"),
            "formatted": data.get("name", {}).get("formatted"),
        },
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", []),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("employeeNumber"),
            "department": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("department"),
            "manager": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("manager"),
        }
    }

def get_user_groups(user_id):
    # Restituisce lista di gruppi (solo displayName e id) in cui l’utente è membro
    user_groups = []
    for group in groups.values():
        members = group.get("members", [])
        if any(m.get("value") == user_id for m in members):
            user_groups.append({
                "value": group["id"],
                "display": group["displayName"]
            })
    return user_groups

@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.get_json()
    # Evita duplicati basandosi su userName
    for user in users.values():
        if user.get("userName") == data.get("userName"):
            # restituisci user esistente con gruppi calcolati
            user_copy = user.copy()
            user_copy["groups"] = get_user_groups(user["id"])
            return jsonify(user_copy), 200
    user_id = data.get("id") or data.get("externalId") or generate_id("user")
    user = build_user(data, user_id)
    users[user_id] = user
    user_copy = user.copy()
    user_copy["groups"] = get_user_groups(user_id)
    return jsonify(user_copy), 201

@app.route("/scim/v2/Users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    user_copy = user.copy()
    user_copy["groups"] = get_user_groups(user_id)
    return jsonify(user_copy)

@app.route("/scim/v2/Users/<user_id>", methods=["PUT"])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json()
    user = build_user(data, user_id)
    users[user_id] = user
    user_copy = user.copy()
    user_copy["groups"] = get_user_groups(user_id)
    return jsonify(user_copy)

@app.route("/scim/v2/Users/<user_id>", methods=["PATCH"])
@require_auth
def patch_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    data = request.get_json()
    for op in data.get("Operations", []):
        if op.get("op", "").lower() == "replace":
            path = op.get("path")
            value = op.get("value")
            if path:
                user[path] = value
            elif isinstance(value, dict):
                user.update(value)
    users[user_id] = user
    user_copy = user.copy()
    user_copy["groups"] = get_user_groups(user_id)
    return jsonify(user_copy)

@app.route("/scim/v2/Users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        # Rimuove utente dai membri dei gruppi
        for group in groups.values():
            group["members"] = [m for m in group.get("members", []) if m["value"] != user_id]
        return '', 204
    abort(404, description="User not found")

# --- GROUPS ---

@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route("/scim/v2/Groups/<group_id>", methods=["GET"])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")
    return jsonify(group)

@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.get_json()
    group_id = data.get("id") or generate_id("group")
    if group_id in groups:
        abort(409, description="Group already exists")
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),  # membri devono avere {"value": user_id, "display": user_display}
        "schemas": data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:Group"])
    }
    groups[group_id] = group
    return jsonify(group), 201

@app.route("/scim/v2/Groups/<group_id>", methods=["PUT"])
@require_auth
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    data = request.get_json()
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:Group"])
    }
    groups[group_id] = group
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["PATCH"])
@require_auth
def patch_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")
    data = request.get_json()
    for op in data.get("Operations", []):
        if op.get("op").lower() == "replace":
            path = op.get("path")
            value = op.get("value")
            if path:
                group[path] = value
            elif isinstance(value, dict):
                group.update(value)
    groups[group_id] = group
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["DELETE"])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        return '', 204
    abort(404, description="Group not found")

@app.route("/")
def root():
    return "SCIM endpoint OK", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
