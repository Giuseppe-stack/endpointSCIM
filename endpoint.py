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

# --- Autenticazione ---
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

# --- Helper ---
def generate_group_id():
    num = 1
    while True:
        gid = f"group{num:03d}"
        if gid not in groups:
            return gid
        num += 1

def enrich_user_with_groups(user):
    """Aggiorna l’utente con la lista di gruppi a cui appartiene"""
    user_groups = []
    for group in groups.values():
        for m in group.get("members", []):
            if m.get("value") == user["id"]:
                user_groups.append({"value": group["id"], "display": group["displayName"]})
    user["groups"] = user_groups
    return user

def update_users_groups_from_group(group):
    """Aggiorna il campo groups degli utenti membri"""
    group_name = group.get("displayName")
    member_ids = [m.get("value") for m in group.get("members", [])]
    for user_id, user in users.items():
        user["groups"] = [g for g in user.get("groups", []) if g.get("value") != group["id"]]
    for member_id in member_ids:
        if member_id in users:
            user = users[member_id]
            if not any(g["value"] == group["id"] for g in user.get("groups", [])):
                user["groups"].append({"value": group["id"], "display": group_name})

def build_user(data, user_id):
    return {
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "emails": data.get("emails", []),
        "name": {
            "givenName": data.get("name", {}).get("givenName"),
            "familyName": data.get("name", {}).get("familyName"),
        },
        "groups": [],
        "schemas": data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:User"])
    }

# --- User Routes ---
@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.get_json()
    user_id = data.get("id") or str(uuid.uuid4())
    user = build_user(data, user_id)
    users[user_id] = user
    # Aggiorna eventuali gruppi già esistenti
    for g in groups.values():
        update_users_groups_from_group(g)
    return jsonify(enrich_user_with_groups(user)), 201

@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    all_users = [enrich_user_with_groups(u) for u in users.values()]
    return jsonify({"Resources": all_users, "totalResults": len(all_users), "itemsPerPage": 100, "startIndex": 1})

@app.route("/scim/v2/Users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    return jsonify(enrich_user_with_groups(user))

@app.route("/scim/v2/Users/<user_id>", methods=["PUT"])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json()
    user = build_user(data, user_id)
    users[user_id] = user
    for g in groups.values():
        update_users_groups_from_group(g)
    return jsonify(enrich_user_with_groups(user))

@app.route("/scim/v2/Users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        for g in groups.values():
            g["members"] = [m for m in g.get("members", []) if m["value"] != user_id]
        return '', 204
    abort(404, description="User not found")

# --- Group Routes ---
@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    return jsonify({"Resources": list(groups.values()), "totalResults": len(groups), "itemsPerPage": 100, "startIndex": 1})

@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.get_json()
    group_id = data.get("id") or generate_group_id()
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    }
    groups[group_id] = group
    update_users_groups_from_group(group)
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
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    }
    groups[group_id] = group
    update_users_groups_from_group(group)
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["DELETE"])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        for user in users.values():
            user["groups"] = [g for g in user.get("groups", []) if g["value"] != group_id]
        return '', 204
    abort(404, description="Group not found")

# --- Service Provider Config ---
@app.route("/scim/v2/ServiceProviderConfig")
def service_provider_config():
    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": True},
        "etag": {"supported": False}
    })

@app.route("/")
def root():
    return "SCIM API"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
