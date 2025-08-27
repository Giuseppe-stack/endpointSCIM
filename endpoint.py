import os
import uuid
from flask import Flask, request, jsonify, abort
from functools import wraps

app = Flask(__name__)

# --- In-memory storage ---
users = {}
groups = {}

# --- Token di autenticazione ---
VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")

# --- Decoratore autenticazione Bearer ---
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.path in ["/", "/favicon.ico", "/scim/v2/ServiceProviderConfig", "/scim/v2/Schemas/Group"]:
            return f(*args, **kwargs)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer"):
            abort(401, description="Missing Bearer token")
        token = auth_header.replace("Bearer", "").strip()
        if token != VALID_TOKEN:
            abort(401, description="Invalid Bearer token")
        return f(*args, **kwargs)
    return decorated

# --- Utility ---
def generate_group_id():
    return str(uuid.uuid4())

def enrich_user_with_groups(user):
    user_groups = []
    for group in groups.values():
        for m in group.get("members", []):
            if m.get("value") == user["id"]:
                user_groups.append({"value": group["id"], "display": group["displayName"]})
    user["groups"] = user_groups
    return user

def update_users_groups_from_group(group):
    group_name = group.get("displayName")
    member_ids = [m.get("value") for m in group.get("members", [])]
    # Rimuovi gruppo dagli utenti non più membri
    for user in users.values():
        user["groups"] = [g for g in user.get("groups", []) if g.get("display") != group_name]
    # Aggiungi gruppo agli utenti membri
    for member_id in member_ids:
        if member_id in users:
            user = users[member_id]
            if not any(g.get("display") == group_name for g in user.get("groups", [])):
                user.setdefault("groups", []).append({"value": group["id"], "display": group_name})

def build_user(data, user_id):
    return {
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
        "displayName": data.get("displayName"),
        "title": data.get("title"),
        "emails": data.get("emails", []),
        "preferredLanguage": data.get("preferredLanguage"),
        "groups": [],
        "name": {
            "givenName": data.get("name", {}).get("givenName"),
            "familyName": data.get("name", {}).get("familyName"),
            "formatted": data.get("name", {}).get("formatted")
        },
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", [])
    }

# --- User Routes ---
@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.get_json()
    for user in users.values():
        if user.get("userName") == data.get("userName"):
            return jsonify(enrich_user_with_groups(user)), 200
    user_id = data.get("id") or data.get("externalId") or str(uuid.uuid4())
    user = build_user(data, user_id)
    users[user_id] = user
    return jsonify(enrich_user_with_groups(user)), 201

@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    filter_param = request.args.get("filter")
    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        matched = [enrich_user_with_groups(u) for u in users.values() if u.get("userName") == username]
        return jsonify({"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100, "startIndex": 1})
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
    return jsonify(enrich_user_with_groups(user))

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
    return jsonify(enrich_user_with_groups(user))

@app.route("/scim/v2/Users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        for group in groups.values():
            group["members"] = [m for m in group.get("members", []) if m["value"] != user_id]
        return "", 204
    abort(404, description="User not found")

# --- Group Routes ---
@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    resources = []
    for group in groups.values():
        g = group.copy()
        g["members"] = g.get("members", [])
        resources.append(g)
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
        abort(404, description="Group not found")
    g = group.copy()
    g["members"] = g.get("members", [])
    return jsonify(g)

@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.get_json()
    group_id = data.get("id") or generate_group_id()
    if group_id in groups:
        abort(409, description="Group already exists")
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

@app.route("/scim/v2/Groups/<group_id>", methods=["PATCH"])
@require_auth
def patch_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")

    data = request.get_json()
    for op in data.get("Operations", []):
        operation = op.get("op", "").lower()
        path = op.get("path", "").lower()
        value = op.get("value", [])

        if operation in ["add", "replace"] and path == "members":
            for member in value:
                user_id = member.get("value")
                if not any(m["value"] == user_id for m in group.get("members", [])):
                    group.setdefault("members", []).append({
                        "value": user_id,
                        "display": member.get("display")
                    })
                if user_id in users:
                    user = users[user_id]
                    if not any(g["value"] == group_id for g in user.get("groups", [])):
                        user.setdefault("groups", []).append({
                            "value": group_id,
                            "display": group["displayName"]
                        })

        elif operation == "remove" and path == "members":
            to_remove = [m.get("value") for m in value]
            group["members"] = [m for m in group.get("members", []) if m["value"] not in to_remove]
            for user_id in to_remove:
                if user_id in users:
                    users[user_id]["groups"] = [g for g in users[user_id]["groups"] if g["value"] != group_id]

    groups[group_id] = group
    return jsonify(group), 200

@app.route("/scim/v2/Groups/<group_id>", methods=["DELETE"])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        for user in users.values():
            user["groups"] = [g for g in user.get("groups", []) if g.get("value") != group_id]
        return "", 204
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
        "etag": {"supported": False},
        "schemasSupported": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        ],
        "authenticationSchemes": [{"type": "oauth2", "name": "Bearer", "description": "OAuth Bearer Token"}]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
