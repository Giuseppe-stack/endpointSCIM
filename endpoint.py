from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token segreto condiviso con Entra ID (solo valore, senza "Bearer ")
VALID_BEARER_TOKEN = "supersegreto"

# Memoria demo per utenti e gruppi
users = {}
groups = {}

@app.before_request
def check_auth():
    # Nessun controllo su ServiceProviderConfig (Entra lo chiama senza token)
    if request.path == '/scim/v2/ServiceProviderConfig':
        print(f"[Auth] Accesso a ServiceProviderConfig senza token")
        return

    auth_header = request.headers.get('Authorization')
    print(f"[Auth] Authorization header: {auth_header}")

    if not auth_header or not auth_header.startswith("Bearer "):
        print("[Auth] Token mancante o header malformato")
        abort(401, description="Unauthorized: Invalid or missing Bearer token")

    token = auth_header.split(" ")[1]
    print(f"[Auth] Token ricevuto: {token}")

    if token != VALID_BEARER_TOKEN:
        print("[Auth] Token non valido")
        abort(401, description="Unauthorized: Invalid Bearer token")

    print("[Auth] Token valido, procedo")

@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    print("[ServiceProviderConfig] Richiesta ricevuta")
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

@app.route('/scim/v2/Users', methods=['POST'])
def create_user():
    data = request.get_json()
    print(f"[CreateUser] Dati ricevuti: {data}")

    user_id = data.get('id', data.get('externalId', f"user-{len(users)+1}"))
    user = {
        "id": user_id,
        "userName": data.get("userName"),
        "name": data.get("name", {}),
        "emails": data.get("emails", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", [])
    }
    users[user_id] = user
    print(f"[CreateUser] Utente creato/aggiornato con ID: {user_id}")

    # Stampa lista utenti attuale
    print(f"[CreateUser] Utenti attualmente provisionati:")
    for u in users.values():
        print(f"  - ID: {u['id']}, userName: {u['userName']}")

    return jsonify(user), 201

@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    print(f"[ListUsers] Richiesta ricevuta. Totale utenti: {len(users)}")
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    print(f"[CreateGroup] Dati ricevuti: {data}")

    group_id = data.get('id', f"group-{len(groups)+1}")
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    print(f"[CreateGroup] Gruppo creato/aggiornato con ID: {group_id}")

    # Stampa lista gruppi attuale
    print(f"[CreateGroup] Gruppi attualmente provisionati:")
    for g in groups.values():
        print(f"  - ID: {g['id']}, displayName: {g['displayName']}")

    return jsonify(group), 201

@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    print(f"[ListGroups] Richiesta ricevuta. Totale gruppi: {len(groups)}")
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    print(f"[DeleteGroup] Richiesta eliminazione gruppo ID: {group_id}")
    if group_id in groups:
        del groups[group_id]
        print(f"[DeleteGroup] Gruppo {group_id} eliminato")
    else:
        print(f"[DeleteGroup] Gruppo {group_id} non trovato")
        abort(404, description="Group not found")

    # Stampa lista gruppi aggiornata
    print(f"[DeleteGroup] Gruppi attualmente provisionati:")
    for g in groups.values():
        print(f"  - ID: {g['id']}, displayName: {g['displayName']}")

    return '', 204

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"Avvio app Flask sulla porta {port}...")
    app.run(host='0.0.0.0', port=port)
