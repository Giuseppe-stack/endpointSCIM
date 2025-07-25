from flask import Flask, request, jsonify, abort
from functools import wraps
import os
import uuid

app = Flask(__name__)

# Token segreto da variabile d'ambiente
VALID_TOKEN = os.environ.get("SCIM_TOKEN", "supersegreto")

# Archiviazione in memoria (per demo)
users = {}
groups = {}

# Decoratore per autenticazione Bearer
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

# Service Provider Configuration
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

# Crea un nuovo utente
@app.route('/scim/v2/Users', methods=['POST'])
@require_auth
def create_user():
    data = request.get_json()
    for user in users.values():
        if user.get("userName") == data.get("userName"):
            return jsonify(user), 200

    user_id = data.get("id") or data.get("externalId") or str(uuid.uuid4())

    user = {
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
            "formatted": data.get("name", {}).get("formatted")
        },
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", []),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("employeeNumber"),
            "department": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("department"),
            "manager": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("manager")
        }
    }

    users[user_id] = user
    return jsonify(user), 201

# Lista utenti
@app.route('/scim/v2/Users', methods=['GET'])
@require_auth
def list_users():
    filter_param = request.args.get('filter')
    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        matched = [u for u in users.values() if u.get("userName") == username]
        return jsonify({"Resources": matched, "totalResults": len(matched), "itemsPerPage": 100, "startIndex": 1})

    return jsonify({"Resources": list(users.values()), "totalResults": len(users), "itemsPerPage": 100, "startIndex": 1})

# Ottieni singolo utente
@app.route('/scim/v2/Users/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    return jsonify(user)

# Aggiorna utente (PUT)
@app.route('/scim/v2/Users/<user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    if user_id not in users:
        abort(404, description="User not found")
    data = request.get_json()
    user = {
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
            "formatted": data.get("name", {}).get("formatted")
        },
        "addresses": data.get("addresses", []),
        "phoneNumbers": data.get("phoneNumbers", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", []),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("employeeNumber"),
            "department": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("department"),
            "manager": data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}).get("manager")
        }
    }
    users[user_id] = user
    return jsonify(user)

# Modifica parziale (PATCH)
@app.route('/scim/v2/Users/<user_id>', methods=['PATCH'])
@require_auth
def patch_user(user_id):
    user = users.get(user_id)
    if not user:
        abort(404, description="User not found")
    data = request.get_json()
    for op in data.get("Operations", []):
        if op.get("op").lower() == "replace":
            path = op.get("path")
            value = op.get("value")
            if path and value:
                user[path] = value
    users[user_id] = user
    return jsonify(user)

# Cancella utente
@app.route('/scim/v2/Users/<user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    if user_id in users:
        del users[user_id]
        return '', 204
    abort(404, description="User not found")

# Gruppi (crea, lista, ottieni, elimina)
@app.route('/scim/v2/Groups', methods=['POST'])
@require_auth
def create_group():
    data = request.get_json()
    group_id = data.get("id") or str(uuid.uuid4())
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    return jsonify(group), 201

@app.route('/scim/v2/Groups', methods=['GET'])
@require_auth
def list_groups():
    return jsonify({"Resources": list(groups.values()), "totalResults": len(groups), "itemsPerPage": 100, "startIndex": 1})

@app.route('/scim/v2/Groups/<group_id>', methods=['GET'])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")
    return jsonify(group)

@app.route('/scim/v2/Groups/<group_id>', methods=['PUT'])
@require_auth
def update_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")
    data = request.get_json()
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    return jsonify(group)

@app.route('/scim/v2/Groups/<group_id>', methods=['PATCH'])
@require_auth
def patch_group(group_id):
    group = groups.get(group_id)
    if not group:
        abort(404, description="Group not found")

    data = request.get_json()
    for op in data.get("Operations", []):
        operation = op.get("op", "").lower()
        path = op.get("path")
        value = op.get("value")

        if operation == "replace":
            if path == "members":
                # Sostituisce completamente la lista dei membri
                group["members"] = value
            elif path:
                # Altri path specifici (non usati tipicamente da Entra ID per i gruppi)
                group[path] = value
            elif isinstance(value, dict):
                # Sostituzione generale (no path): unione dizionari
                group.update(value)

        elif operation == "add" and path == "members":
            # Aggiunge nuovi membri alla lista esistente
            existing = {m["value"] for m in group.get("members", [])}
            for member in value:
                if member["value"] not in existing:
                    group.setdefault("members", []).append(member)

        elif operation == "remove" and path == "members":
            group["members"] = []

    groups[group_id] = group
    return jsonify(group)



@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
@require_auth
def delete_group(group_id):
    if group_id in groups:
        del groups[group_id]
        return '', 204
    abort(404, description="Group not found")

@app.route('/')
@app.route('/favicon.ico')
def root():
    return "SCIM endpoint OK", 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
