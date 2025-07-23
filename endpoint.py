from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token segreto per autenticazione Bearer
VALID_TOKEN = "supersegreto"

# Archivi in memoria
users = {}
groups = {}

# Middleware autenticazione
@app.before_request
def check_auth():
    if request.path == '/scim/v2/ServiceProviderConfig':
        print("[Auth] Nessuna autenticazione per ServiceProviderConfig")
        return

    auth_header = request.headers.get('Authorization', '')
    print(f"[Auth] Authorization header: '{auth_header}'")

    if not auth_header.lower().startswith("bearer"):
        print("[Auth] Errore: Header mancante o senza 'Bearer'")
        abort(401, description="Unauthorized: Missing Bearer token")

    token = auth_header.replace("Bearer", "").strip()
    print(f"[Auth] Token estratto: '{token}'")

    if token != VALID_TOKEN:
        print("[Auth] Errore: Token non valido")
        abort(401, description="Unauthorized: Invalid Bearer token")

    print("[Auth] Autenticazione riuscita")

# Configurazione SCIM
@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    print("[API] ServiceProviderConfig richiesto")
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

# Creazione utente
@app.route('/scim/v2/Users', methods=['POST'])
def create_user():
    data = request.get_json()
    print(f"[API] Richiesta creazione utente: {data}")

    requested_username = data.get("userName")
    for existing in users.values():
        if existing.get("userName") == requested_username:
            print(f"[Error] userName duplicato: {requested_username}")
            abort(409, description="Conflict: userName already exists")

    user_id = data.get('id') or data.get('externalId') or f"user-{len(users)+1}"
    user = {
        "id": user_id,
        "userName": requested_username,
        "name": data.get("name", {}),
        "emails": data.get("emails", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", [])
    }
    users[user_id] = user
    print(f"[Data] ✅ Utente salvato: {user_id}")
    return jsonify(user), 201

# Lista utenti
@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    print("[API] Lista utenti richiesta")
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# Creazione gruppo
@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    print(f"[API] Richiesta creazione gruppo: {data}")
    group_id = data.get('id') or f"group-{len(groups)+1}"
    group = {
        "id": group_id,
        "displayName": data.get("displayName"),
        "members": data.get("members", []),
        "schemas": data.get("schemas", [])
    }
    groups[group_id] = group
    print(f"[Data] Gruppo salvato: {group_id}")
    return jsonify(group), 201

# Lista gruppi
@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    print("[API] Lista gruppi richiesta")
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# Recupera gruppo (necessario per Entra ID)
@app.route('/scim/v2/Groups/<group_id>', methods=['GET'])
def get_group(group_id):
    print(f"[API] 🔍 Recupero gruppo richiesto: {group_id}")
    group = groups.get(group_id)
    if not group:
        print(f"[Error] Gruppo non trovato: {group_id}")
        abort(404, description="Group not found")
    return jsonify(group)

# Cancellazione gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    print(f"[API] Richiesta eliminazione gruppo: {group_id}")
    if group_id in groups:
        del groups[group_id]
        print(f"[Data] Gruppo eliminato: {group_id}")
        return '', 204
    else:
        print(f"[Error] Gruppo non trovato: {group_id}")
        abort(404, description="Group not found")

# Avvio server
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[Startup] Avvio app SCIM su http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port)
