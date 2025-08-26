import os
import uuid
from flask import Flask, request, jsonify, abort
from functools import wraps

app = Flask(__name__)

# In-memory storage
users = {}
groups = {}

# Token SCIM
VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")

# --- Autenticazione Bearer ---
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

# --- Utility ---
def generate_id():
    return str(uuid.uuid4())

def enrich_user(user):
    """Aggiunge i gruppi a cui l'utente appartiene."""
    user_copy = user.copy()
    user_groups = []
    for group in groups.values():
        for member in group.get("members", []):
            if member.get("value") == user["id"]:
                user_groups.append({"value": group["id"], "display": group["displayName"]})
    user_copy["groups"] = user_groups
    return user_copy

def update_users_from_group(group):
    """Aggiorna i gruppi degli utenti in base ai membri del gruppo."""
    group_id = group["id"]
    member_ids = [m["value"] for m in group.get("members", [])]

    # Rimuove il gruppo dagli utenti non più membri
    for user in users.values():
        user["groups"] = [g for g in user.get("groups", []) if g.get("value") != group_id]

    # Aggiunge il gruppo agli utenti membri
    for member_id in member_ids:
        if member_id in users:
            user = users[member_id]
            if not any(g.get("value") == group_id for g in user.get("groups", [])):
                user.setdefault("groups", []).append({"value": group_id, "display": group["displayName"]})

# --- Users ---
@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.get_json()
    user_id = data.get("id") or generate_id()
    if user_id in users:
        return jsonify(enrich_user(users[user_id])), 200
    user = {
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "emails": data.get("emails", []),
        "name": data.get("name", {}),
        "groups": []
    }
    users[user_id] = user
    return jsonify(enrich_user(user)), 201

@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    filter_param = request.args.get("filter")
    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        matched = [enrich_user(u) for u in users.values() if u.get("userName") == username]
        return jsonify({"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100, "startIndex": 1})
    all_users = [enrich_user(u) for u in users.values()]
    return jsonify({"Resources": all_users, "totalResults": len(all_users), "itemsPerPage": 100, "startIndex": 1})

@app.route("/scim/v2/Users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404)
    return jsonify(enrich_user(user))

@app.route("/scim/v2/Users/<user_id>", methods=["PUT"])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404)
    data = request.get_json()
    user = {
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "emails": data.get("emails", []),
        "name": data.get("name", {}),
        "groups": users[user_id].get("groups", [])
    }
    users[user_id] = user
    return jsonify(enrich_user(user))

@app.route("/scim/v2/Users/<user_id>", methods=["PATCH"])
@require_auth
def patch_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404)
    data = request.get_json()
    for op in data.get("Operations", []):
        if op.get("op", "").lower() == "replace":
            value = op.get("value", {})
            if isinstance(value, dict):
                user.update(value)
    users[user_id] = user
    return jsonify(enrich_user(user))

@app.route("/scim/v2/Users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        for group in groups.values():
            group["members"] = [m for m in group.get("members", []) if m["value"] != user_id]
        return "", 204
    abort(404)

# --- Groups ---
@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.get_json()
    group_id = data.get("id") or generate_id()
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    }
    groups[group_id] = group
    update_users_from_group(group)
    return jsonify(group), 201

@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    resources = [g for g in groups.values()]
    return jsonify({
        "Resources": resources,
        "totalResults": len(resources),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route("/scim/v2/Groups/<group_id>", methods=["GET"])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404)
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["PUT"])
@require_auth
def update_group(group_id):
    if group_id not in groups:
        abort(404)
    data = request.get_json()
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    }
    groups[group_id] = group
    update_users_from_group(group)
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["PATCH"])
@require_auth
def patch_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404)
    data = request.get_json()
    for op in data.get("Operations", []):
        operation = op.get("op", "").lower()
        value = op.get("value", [])

        if operation == "replace":
            group["members"] = value

        elif operation == "add":
            existing_ids = {m["value"] for m in group.get("members", [])}
            for member in value:
                if member["value"] not in existing_ids:
                    group.setdefault("members", []).append(member)

        elif operation == "remove":
            remove_ids = [m["value"] for m in value]
            group["members"] = [m for m in group.get("members", []) if m["value"] not in remove_ids]

    update_users_from_group(group)
    groups[group_id] = group
    return jsonify(group)

@app.route("/scim/v2/Groups/<group_id>", methods=["DELETE"])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        for user in users.values():
            user["groups"] = [g for g in user.get("groups", []) if g.get("value") != group_id]
        return "", 204
    abort(404)

# --- Service Provider Config ---
@app.route("/scim/v2/ServiceProviderConfig")
def service_provider_config():
    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "filter": {"supported": True, "maxResults": 200},
        "sort": {"supported": True},
        "schemasSupported": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        ],
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer Token",
                "primary": True
            }
        ]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
