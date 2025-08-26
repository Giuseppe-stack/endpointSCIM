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
    """Aggiunge i gruppi di cui l'utente è membro."""
    user_groups = []
    for group in groups.values():
        for m in group.get("members", []):
            if m.get("value") == user["id"]:
                user_groups.append({"value": group["id"], "display": group["displayName"]})
    user["groups"] = user_groups
    return user

def update_users_groups_from_group(group):
    """Aggiorna gli utenti in base ai membri del gruppo."""
    group_name = group.get("displayName")
    member_ids = [m.get("value") for m in group.get("members", [])]

    # Rimuovi il gruppo dagli utenti non più membri
    for user in users.values():
        user["groups"] = [g for g in user.get("groups", []) if g.get("display") != group_name]

    # Aggiungi gruppo agli utenti membri
    for member_id in member_ids:
        if member_id in users:
            user = users[member_id]
            if not any(g.get("display") == group_name for g in user.get("groups", [])):
                user["groups"].append({"value": group["id"], "display": group_name})

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

    # Forza l'aggiornamento dei gruppi
    for group in groups.values():
        if any(m.get("value") == user_id for m in group.get("members", [])):
            update_users_groups_from_group(group)

    return jsonify(enrich_user_with_groups(user)), 201

@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    filter_param = request.args.get("filter")
    all_users = [enrich_user_with_groups(u) for u in users.values()]

    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        matched = [u for u in all_users if u.get("userName") == username]
        return jsonify({"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100, "startIndex": 1})

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

    # Forza aggiornamento dei gruppi
    for group in groups.values():
        update_users_groups_from_group(group)

    return jsonify(enrich_user_with_groups(user))

# --- Group Routes ---
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

    # Forza aggiornamento degli utenti
    update_users_groups_from_group(group)

    return jsonify(group), 201

@app.route("/scim/v2/Groups/<group_id>", methods=["GET"])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")
    return jsonify(group)

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

# --- Forza popolamento groups/members sempre ---
def populate_all_groups_users():
    for group in groups.values():
        update_users_groups_from_group(group)

@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    populate_all_groups_users()
    resources = []
    for group in groups.values():
        g = group.copy()
        resources.append(g)
    return jsonify({"Resources": resources, "totalResults": len(resources), "itemsPerPage": 100, "startIndex": 1})

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
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer Token",
                "description": "Bearer Token Authorization",
                "specUri": "https://tools.ietf.org/html/rfc6750",
                "documentationUri": "",
                "primary": True
            }
        ]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
