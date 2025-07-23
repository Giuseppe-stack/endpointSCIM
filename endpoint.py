from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)

# 🔐 Token valido da usare in Entra ID e test CURL
VALID_TOKEN = "supersegreto"

# 🧠 Memoria temporanea
users = {}
groups = {}

# 🔐 Middleware autenticazione token
@app.before_request
def check_auth():
    public_paths = ['/', '/favicon.ico', '/scim/v2/ServiceProviderConfig']
    if request.path in public_paths:
        print(f"[Public] Accesso libero a: {request.path}")
        return

    auth_header = request.headers.get('Authorization')
    print(f"[Auth] Header ricevuto: {auth_header}")

    if not auth_header or not auth_header.lower().startswith("bearer"):
        print("[Auth] Header mancante o non inizia con 'Bearer'")
        abort(401, description="Unauthorized: Missing Bearer token")

    token = auth_header.replace("Bearer", "").strip()
    print(f"[Auth] Token estratto: '{token}'")

    if token != VALID_TOKEN:
        print("[Auth] Token non valido")
        abort(401, description="Unauthorized: Invalid Bearer token")

    print("[Auth] Autenticazione riuscita")

# 🏠 Home page
@app.route('/', methods=['GET'])
def home():
    return "SCIM Server è attivo. Usa /scim/v2/Users o /scim/v2/Groups"

# 🖼️ Favicon silenziata
@app.route('/favicon.ico')
def favicon():
    return '', 204

# ⚙️ Configurazione ServiceProvider
@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    print("[API] 📡 ServiceProviderConfig richiesto")
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

# 👤 Creazione utente
@app.route('/scim/v2/Users', methods=['POST'])
def create_user():
    data = request.get_json()
    print(f"[API] Creazione utente richiesta: {data}")
    user_id = data.get('id') or data.get('externalId') or f"user-{len(users)+1}"
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

# 📋 Lista utenti
@app.route('/scim/v2/Users', methods=['GET'])
def list_users():
    print("[API] Lista utenti richiesta")
    return jsonify({
        "Resources": list(users.values()),
        "totalResults": len(users),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# 👥 Creazione gruppo
@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    print(f"[API] Creazione gruppo richiesta: {data}")
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

# 📋 Lista gruppi
@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    print("[API] Lista gruppi richiesta")
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

# ❌ Cancellazione gruppo
@app.route('/scim/v2/Groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    print(f"[API] Eliminazione gruppo richiesta: {group_id}")
    if group_id in groups:
        del groups[group_id]
        print(f"[Data] Gruppo eliminato: {group_id}")
        return '', 204
    else:
        print(f"[Error] Gruppo non trovato: {group_id}")
        abort(404, description="Group not found")

# 🚀 Avvio app
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[Startup] Avvio SCIM su http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port)
