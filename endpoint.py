from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# Token segreto per autenticazione Bearer
VALID_TOKEN = "supersegreto"

# Archiviazione in memoria
users = {}
groups = {}

# Escludi alcune rotte da autenticazione
EXCLUDED_PATHS = [
    "/scim/v2/ServiceProviderConfig",
    "/favicon.ico",
    "/"
]

@app.before_request
def check_auth():
    if request.path in EXCLUDED_PATHS:
        print(f"[Auth] Accesso libero a {request.path}")
        return

    auth_header = request.headers.get("Authorization", "")
    print(f"[Auth] Authorization header: {auth_header}")

    if not auth_header.lower().startswith("bearer"):
        print("[Auth] Header mancante o senza 'Bearer'")
        abort(401, description="Unauthorized: Missing Bearer token")

    token = auth_header.replace("Bearer", "").strip()
    print(f"[Auth] Token estratto: '{token}'")

    if token != VALID_TOKEN:
        print("[Auth] Token non valido")
        abort(401, description="Unauthorized: Invalid Bearer token")

    print("[Auth] Autenticazione riuscita")

# ServiceProviderConfig richiesto da Entra ID
@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    print("[API] 🛠ServiceProviderConfig richiesto")
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
    print(f"[API] Creazione utente richiesta: {data}")

    # Verifica se userName esiste già
    for user in users.values():
        if user.get("userName") == data.get("userName"):
            print("[API] Utente già presente con userName, restituisco esistente")
            return jsonify(user), 200

    user_id = data.get("id") or data.get("externalId") or f"user-{len(users)+1}"
    user = {
        "id": user_id,
        "userName": data.get("userName"),
        "name": data.get("name", {}),
        "emails": data.get("emails", []),
        "externalId": data.get("externalId"),
        "schemas": data.get("schemas", [])
    }
    users[user_id] = user
    print(f"[Data] Utente salvato: {user_id}")
    return jsonify(user), 201

# Lista utenti con supporto filtro
@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    filter_param = request.args.get('filter')
    print(f"[API] Lista utenti richiesta - Filtro: {filter_param}")

    if filter_param and "userName eq " in filter_param:
        username = filter_param.split("userName eq ")[1].strip('"')
        matched = [u for u in users.values() if u.get("userName") == username]
        print(f"[API] Utenti trovati: {len(matched)}")
        return jsonify({
            "Resources": matched,
            "totalResults": len(matched),
            "itemsPerPage": 100,
            "startIndex": 1
        })

    print(f"[API] Restituisco tutti gli utenti")
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
    print(f"[API] Creazione gruppo richiesta: {data}")
    group_id = data.get("id") or f"group-{len(groups)+1}"
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
    print(f"[API] Lista gruppi richiesta")
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# Cancellazione gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    print(f"[API] Richiesta cancellazione gruppo: {group_id}")
    if group_id in groups:
        del groups[group_id]
        print(f"[Data] Gruppo eliminato: {group_id}")
        return '', 204
    else:
        print(f"[Error] Gruppo non trovato: {group_id}")
        abort(404, description="Group not found")

# Gestione root path e favicon (no 401)
@app.route('/', methods=['GET'])
@app.route('/favicon.ico', methods=['GET'])
def root():
    return "SCIM server OK", 200

# Avvio server
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[Startup] SCIM server attivo su http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port)
