from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# Token di esempio (da sostituire con uno reale)
VALID_BEARER_TOKEN = "Bearer eyJhbGciOi..."

# In-memory storage per i gruppi
groups = {}

# Middleware per autenticazione Bearer
@app.before_request
def check_auth():
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != VALID_BEARER_TOKEN:
        abort(401, description="Unauthorized: Invalid or missing Bearer token")

@app.route('/scim/v2/ServiceProviderConfig', methods=['GET'])
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
            "description": "SCIM Bearer Token",
            "specUri": "http://www.rfc-editor.org/info/rfc6750"
        }]
    })

@app.route('/scim/v2/Groups', methods=['POST'])
def create_group():
    data = request.get_json()
    group_id = data.get('id', f"group-{len(groups)+1}")
    groups[group_id] = data
    return jsonify(data), 201

@app.route('/scim/v2/Groups/<group_id>', methods=['GET', 'PATCH', 'DELETE'])
def manage_group(group_id):
    if group_id not in groups:
        abort(404, description="Group not found")

    if request.method == 'GET':
        return jsonify(groups[group_id])
    'PATCH'
        patch_data = request.get_json()
        for op in patch_data.get('Operations', []):
            if op['op'] == 'replace':
                for key, value in op['value'].items():
                    groups[group_id][key] = value
        return jsonify(groups[group_id])
    elif request.method == 'DELETE':
        del groups[group_id]
        return '', 204

@app.route('/scim/v2/Groups', methods=['GET'])
def list_groups():
    return jsonify({
        "Resources": list(groups.values()),
        "totalResults": len(groups),
        "itemsPerPage": 100,
        "startIndex": 1
    })

if __name__ == '__main__':
    app.run(port=5000)
