from flask import Flask, request, jsonify
from uuid import uuid4

app = Flask(__name__)

# In-memory stores
users = {}
groups = {}

# Authentication decorator
def require_auth(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if auth_header != "Bearer supersegreto":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# Create User
@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.json
    user_id = str(uuid4())
    data["id"] = user_id
    users[user_id] = data
    return jsonify(data), 201

# Get User by ID
@app.route("/scim/v2/Users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    user = users.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404

# Create Group
@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.json
    group_id = str(uuid4())
    data["id"] = group_id
    data["members"] = []  # initially empty
    groups[group_id] = data
    return jsonify(data), 201

# Get Group by ID
@app.route("/scim/v2/Groups/<group_id>", methods=["GET"])
@require_auth
def get_group(group_id):
    group = groups.get(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404

    enriched_members = []
    for user in users.values():
        if user.get("groupId") == group_id:
            enriched_members.append({
                "value": user["id"],
                "display": user.get("displayName", user.get("userName"))
            })

    group["members"] = enriched_members
    return jsonify(group)

# List all Groups
@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    result = []
    for group in groups.values():
        enriched_members = []
        for user in users.values():
            if user.get("groupId") == group["id"]:
                enriched_members.append({
                    "value": user["id"],
                    "display": user.get("displayName", user.get("userName"))
                })
        group_copy = group.copy()
        group_copy["members"] = enriched_members
        result.append(group_copy)
    return jsonify(result)

# Run
if __name__ == "__main__":
    app.run(debug=True)
