from flask import Flask, request, jsonify, abort
from functools import wraps
import os
import uuid

app = Flask(__name__)

# =============================
# In-memory storage (no persistence)
# =============================
users = {}
groups = {}

# =============================
# Auth (Bearer)
# =============================
VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")
EXCLUDED_PATHS = {
    "/",
    "/favicon.ico",
    "/scim/v2/ServiceProviderConfig",
    "/scim/v2/Schemas/Group",
    "/scim/v2/Schemas/User",
}

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.path in EXCLUDED_PATHS:
            return f(*args, **kwargs)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer"):
            abort(401, description="Missing Bearer token")
        token = auth_header.replace("Bearer", "").strip()
        if token != VALID_TOKEN:
            abort(401, description="Invalid Bearer token")
        return f(*args, **kwargs)
    return decorated

# =============================
# Helpers
# =============================

def generate_id():
    return str(uuid.uuid4())


def build_user(data, user_id):
    # Base SCIM user model (minimal) + groups (computed)
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
        "schemas": data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:User"]),
        # This field is NOT authoritative; it is recomputed before responses
        "groups": data.get("groups", []),
    }


def resolve_user_ref(ref_value):
    """Resolve a member reference to a concrete user id.
    We try by ID, then by userName, then by externalId.
    Returns (user_id or None).
    """
    if not ref_value:
        return None
    # direct id
    if ref_value in users:
        return ref_value
    # by userName
    for uid, u in users.items():
        if u.get("userName") == ref_value:
            return uid
    # by externalId
    for uid, u in users.items():
        if u.get("externalId") == ref_value:
            return uid
    return None


def enrich_user_with_groups(user):
    """Compute the user's groups from the canonical groups->members relation."""
    computed = []
    for g in groups.values():
        for m in g.get("members", []) or []:
            if m.get("value") == user["id"]:
                computed.append({"value": g["id"], "display": g.get("displayName")})
    u = dict(user)
    u["groups"] = computed
    return u


def ensure_group_members_from_users():
    """Reconstruct group.members from users[*].groups to avoid empty lists across cycles."""
    for g in groups.values():
        wanted = set()
        # collect desired members from users' groups links
        for uid, u in users.items():
            for ug in u.get("groups", []) or []:
                if ug.get("value") == g["id"]:
                    wanted.add(uid)
        # merge with existing explicit members
        current = {m.get("value") for m in g.get("members", []) or []}
        final_ids = current.union(wanted)
        g["members"] = [
            {"value": uid, "display": users.get(uid, {}).get("displayName")}
            for uid in final_ids
            if uid in users
        ]


def ensure_users_groups_from_groups():
    """Reconstruct users[*].groups from groups[*].members to keep bidirectional consistency."""
    for uid, u in users.items():
        memberships = []
        for g in groups.values():
            for m in g.get("members", []) or []:
                if m.get("value") == uid:
                    memberships.append({"value": g["id"], "display": g.get("displayName")})
        u["groups"] = memberships


def sync_bidirectional():
    """Call both reconcilers to keep data coherent before answering GETs and after writes."""
    ensure_group_members_from_users()
    ensure_users_groups_from_groups()


# =============================
# Service Provider Config & Schemas
# =============================
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


@app.route('/scim/v2/Schemas/Group', methods=['GET'])
@require_auth
def schema_group():
    return jsonify({
        "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
        "name": "Group",
        "description": "Group schema",
        "attributes": [
            {"name": "displayName", "type": "string", "multiValued": False, "required": True},
            {"name": "members", "type": "complex", "multiValued": True, "required": False},
        ]
    })


@app.route('/scim/v2/Schemas/User', methods=['GET'])
@require_auth
def schema_user():
    return jsonify({
        "id": "urn:ietf:params:scim:schemas:core:2.0:User",
        "name": "User",
        "description": "User schema",
    })

# =============================
# Users
# =============================
@app.route('/scim/v2/Users', methods=['POST'])
@require_auth
def create_user():
    data = request.get_json(force=True)
    # Idempotenza su userName
    for u in users.values():
        if u.get("userName") == data.get("userName"):
            sync_bidirectional()
            return jsonify(enrich_user_with_groups(u)), 200

    user_id = data.get("id") or data.get("externalId") or generate_id()
    user = build_user(data, user_id)
    users[user_id] = user

    # Se arrivano gruppi nella POST, prova a collegarli
    for gref in user.get("groups", []) or []:
        gid = gref.get("value")
        if gid and gid in groups:
            grp = groups[gid]
            if not any(m.get("value") == user_id for m in grp.get("members", []) or []):
                grp.setdefault("members", []).append({"value": user_id, "display": user.get("displayName")})

    sync_bidirectional()
    return jsonify(enrich_user_with_groups(user)), 201


@app.route('/scim/v2/Users', methods=['GET'])
@require_auth
def list_users():
    sync_bidirectional()
    filter_param = request.args.get('filter')
    resources = []
    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        for u in users.values():
            if u.get("userName") == username:
                resources.append(enrich_user_with_groups(u))
    else:
        resources = [enrich_user_with_groups(u) for u in users.values()]
    return jsonify({
        "Resources": resources,
        "totalResults": len(resources),
        "itemsPerPage": 100,
        "startIndex": 1
    })


@app.route('/scim/v2/Users/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    sync_bidirectional()
    u = users.get(user_id)
    if not u:
        abort(404, description="User not found")
    return jsonify(enrich_user_with_groups(u))


@app.route('/scim/v2/Users/<user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json(force=True)
    user = build_user(data, user_id)
    users[user_id] = user
    sync_bidirectional()
    return jsonify(enrich_user_with_groups(user))


@app.route('/scim/v2/Users/<user_id>', methods=['PATCH'])
@require_auth
def patch_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    body = request.get_json(force=True) or {}
    for op in body.get("Operations", []):
        operation = op.get("op", "").lower()
        path = op.get("path")
        value = op.get("value")
        if operation == "replace":
            if path:
                # simple path (e.g., displayName, active, name.givenName)
                if "." in path:
                    head, tail = path.split(".", 1)
                    user.setdefault(head, {})
                    user[head][tail] = value
                else:
                    user[path] = value
            elif isinstance(value, dict):
                # bulk replace object
                user.update(value)
        elif operation == "add" and path == "groups":
            # not typical for Entra, but handle anyway
            for gref in value or []:
                gid = gref.get("value")
                if gid and gid in groups:
                    grp = groups[gid]
                    if not any(m.get("value") == user_id for m in grp.get("members", []) or []):
                        grp.setdefault("members", []).append({"value": user_id, "display": user.get("displayName")})
    users[user_id] = user
    sync_bidirectional()
    return jsonify(enrich_user_with_groups(user))


@app.route('/scim/v2/Users/<user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        # clean up group memberships
        for g in groups.values():
            g["members"] = [m for m in g.get("members", []) or [] if m.get("value") != user_id]
        sync_bidirectional()
        return '', 204
    abort(404, description="User not found")


# =============================
# Groups
# =============================
@app.route('/scim/v2/Groups', methods=['POST'])
@require_auth
def create_group():
    data = request.get_json(force=True)
    group_id = data.get("id") or data.get("externalId") or generate_id()
    grp = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": [],
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "externalId": data.get("externalId"),
    }

    # Seed members if provided (resolve references)
    for m in data.get("members", []) or []:
        ref = m.get("value")
        uid = resolve_user_ref(ref)
        if uid and not any(x.get("value") == uid for x in grp["members"]):
            grp["members"].append({"value": uid, "display": users.get(uid, {}).get("displayName")})
            users[uid].setdefault("groups", []).append({"value": group_id, "display": grp["displayName"]})

    groups[group_id] = grp
    sync_bidirectional()
    return jsonify(grp), 201


@app.route('/scim/v2/Groups', methods=['GET'])
@require_auth
def list_groups():
    sync_bidirectional()
    resources = []
    for g in groups.values():
        resources.append({
            "id": g["id"],
            "displayName": g.get("displayName"),
            "members": g.get("members", []),
            "schemas": g.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:Group"]),
        })
    return jsonify({
        "Resources": resources,
        "totalResults": len(resources),
        "itemsPerPage": 100,
        "startIndex": 1
    })


@app.route('/scim/v2/Groups/<group_id>', methods=['GET'])
@require_auth
def get_group(group_id):
    sync_bidirectional()
    g = groups.get(group_id)
    if not g:
        abort(404, description="Group not found")
    return jsonify({
        "id": g["id"],
        "displayName": g.get("displayName"),
        "members": g.get("members", []),
        "schemas": g.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:Group"]),
    })


@app.route('/scim/v2/Groups/<group_id>', methods=['PUT'])
@require_auth
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    data = request.get_json(force=True)
    grp = groups[group_id]
    grp["displayName"] = data.get("displayName")
    grp["schemas"] = ["urn:ietf:params:scim:schemas:core:2.0:Group"]

    # Replace membership entirely
    new_members = []
    for m in data.get("members", []) or []:
        uid = resolve_user_ref(m.get("value"))
        if uid and not any(x.get("value") == uid for x in new_members):
            new_members.append({"value": uid, "display": users.get(uid, {}).get("displayName")})
    grp["members"] = new_members

    # Recompute users[*].groups links
    for u in users.values():
        u["groups"] = [x for x in u.get("groups", []) if x.get("value") != group_id]
    for mem in grp["members"]:
        uid = mem.get("value")
        if uid in users:
            users[uid].setdefault("groups", []).append({"value": group_id, "display": grp["displayName"]})

    sync_bidirectional()
    return jsonify(grp)


@app.route('/scim/v2/Groups/<group_id>', methods=['PATCH'])
@require_auth
def patch_group(group_id):
    grp = groups.get(group_id)
    if not grp:
        abort(404, description="Group not found")
    body = request.get_json(force=True) or {}

    def add_member(uid):
        if uid and not any(m.get("value") == uid for m in grp.get("members", []) or []):
            grp.setdefault("members", []).append({"value": uid, "display": users.get(uid, {}).get("displayName")})
        if uid in users and not any(g.get("value") == group_id for g in users[uid].get("groups", [])):
            users[uid].setdefault("groups", []).append({"value": group_id, "display": grp.get("displayName")})

    def remove_member(uid):
        grp["members"] = [m for m in grp.get("members", []) or [] if m.get("value") != uid]
        if uid in users:
            users[uid]["groups"] = [g for g in users[uid].get("groups", []) if g.get("value") != group_id]

    for op in body.get("Operations", []):
        operation = op.get("op", "").lower()
        path = (op.get("path") or '').strip()
        value = op.get("value")

        # PATCH displayName (replace)
        if operation == "replace" and (path == "displayName" or path == "") and isinstance(value, (str, dict)):
            if isinstance(value, str):
                grp["displayName"] = value
            elif isinstance(value, dict) and "displayName" in value:
                grp["displayName"] = value["displayName"]
            continue

        # Handle members add/replace
        if operation in ("add", "replace"):
            # Case: path == "members" with full list
            if path.lower() == "members":
                new_vals = value or []
                for m in new_vals:
                    uid = resolve_user_ref(m.get("value"))
                    add_member(uid)
                continue

            # Case: path like members[value eq "<id>"]
            if path.lower().startswith("members[value eq "):
                # extract id within quotes
                try:
                    member_id = path.split("members[value eq ", 1)[1].strip().strip(']').strip().strip('"')
                except Exception:
                    member_id = None
                uid = resolve_user_ref(member_id)
                add_member(uid)
                continue

        # Handle remove for members
        if operation == "remove":
            if path.lower() == "members":
                # Remove list provided in value
                to_remove = []
                for m in (value or []):
                    rid = resolve_user_ref(m.get("value"))
                    if rid:
                        to_remove.append(rid)
                for rid in to_remove:
                    remove_member(rid)
                continue

            if path.lower().startswith("members[value eq "):
                try:
                    member_id = path.split("members[value eq ", 1)[1].strip().strip(']').strip().strip('"')
                except Exception:
                    member_id = None
                rid = resolve_user_ref(member_id)
                remove_member(rid)
                continue

    sync_bidirectional()
    return jsonify(grp)


@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        # remove back-links from users
        for u in users.values():
            u["groups"] = [g for g in u.get("groups", []) if g.get("value") != group_id]
        del groups[group_id]
        sync_bidirectional()
        return '', 204
    abort(404, description="Group not found")


# =============================
# Root & health
# =============================
@app.route('/')
@app.route('/favicon.ico')
def root():
    return "SCIM endpoint OK", 200


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
