from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from models import User, FriendRequest, Friends, Message, db
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from werkzeug.security import generate_password_hash
from flask_cors import CORS
from dotenv import load_dotenv
import os

app = Flask(__name__)
CORS(app)  
socketio = SocketIO(app, cors_allowed_origins="*")

load_dotenv()
KEY = os.getenv("KEY")

if KEY is None:
    raise ValueError("Key not found! Set KEY in your environment.")
app.config['SQLALCHEMY_DATABASE_URI'] = KEY
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'yoursecretkey'  
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  

db.init_app(app)

jwt = JWTManager(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect('register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    if request.method == 'POST':
        if request.content_type != 'application/json':
            return jsonify({"error": "Invalid content type, expected 'application/json'"}), 415
        
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        hashed_password = generate_password_hash(password)

        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        data = request.get_json()  
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password): 
            access_token = create_access_token(identity=str(user.id))

            return jsonify({"access_token": access_token, "message": "Login successful"}), 200

        return jsonify({"message": "Invalid username or password"}), 401

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')  

@app.route('/dashboard/data', methods=['GET'])
@jwt_required()
def dashboard_data():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"username": user.username, "message": "Welcome"}), 200

@app.route('/search', methods=['GET'])
def search():
    return render_template('search.html')

@app.route('/search/data', methods=['GET'])
@jwt_required()
def search_data():
    query = request.args.get('query')
    current_user_id = int(get_jwt_identity())  

    if not query:
        return jsonify({"message": "Please enter a username to search.", "status": "warning"}), 400

    users = User.query.filter(
        User.username.ilike(f"%{query}%"),
        User.id != current_user_id
    ).all()

    if not users:
        return jsonify({"message": "No users found.", "status": "info"}), 404

    users_json = [{"id": user.id, "username": user.username} for user in users]

    return jsonify({"users": users_json, "status": "success"}), 200

def check_if_friends(user1_id, user2_id):
    return Friends.query.filter(
        ((Friends.user1_id == user1_id) & (Friends.user2_id == user2_id)) |
        ((Friends.user1_id == user2_id) & (Friends.user2_id == user1_id))
    ).first() is not None

@app.route('/send_friend_request/<int:receiver_id>', methods=['POST'])
@jwt_required()
def send_friend_request(receiver_id):
    current_user_id = int(get_jwt_identity())
    receiver = User.query.get(receiver_id)

    if not receiver:
        return jsonify({"message": "User not found!", "status": "danger"}), 404

    if receiver.id == current_user_id:
        return jsonify({"message": "You cannot send a friend request to yourself!", "status": "warning"}), 400

    if check_if_friends(current_user_id, receiver.id):
        return jsonify({"message": "You are already friends!", "status": "info"}), 400

    existing_request = FriendRequest.query.filter_by(sender_id=current_user_id, receiver_id=receiver.id).first()
    if existing_request:
        return jsonify({"message": "Friend request already sent!", "status": "info"}), 400

    friend_request = FriendRequest(sender_id=current_user_id, receiver_id=receiver.id)
    db.session.add(friend_request)
    db.session.commit()

    return jsonify({"message": "Friend request sent successfully!", "status": "success"}), 200

@app.route('/friend_requests', methods= ['GET'])
def friend_requests():
    return render_template('friend_requests.html')

@app.route('/friend_requests/data', methods=['GET'])
@jwt_required()
def friend_requests_data():
    current_user_id = int(get_jwt_identity())
    requests = FriendRequest.query.filter_by(receiver_id=current_user_id).all()

    if not requests:
        return jsonify({"message": "No friend requests found.", "status": "info"}), 404

    requests_json = [
        {
            "id": request.id,
            "sender_id": request.sender_id,
            "sender_username": User.query.get(request.sender_id).username
        }
        for request in requests
    ]

    return jsonify({"requests": requests_json, "status": "success"}), 200

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
@jwt_required()
def accept_friend_request(request_id):
    current_user_id = int(get_jwt_identity())
    friend_request = FriendRequest.query.get(request_id)

    if not friend_request or friend_request.receiver_id != current_user_id:
        return jsonify({"message": "Invalid friend request"}), 400

    if check_if_friends(friend_request.sender_id, friend_request.receiver_id):
        return jsonify({"message": "You are already friends!"}), 400

    new_friendship = Friends(user1_id=friend_request.sender_id, user2_id=friend_request.receiver_id)
    db.session.add(new_friendship)

    db.session.delete(friend_request)
    db.session.commit()

    return jsonify({"message": "Friend request accepted!"}), 200

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
@jwt_required()
def reject_friend_request(request_id):
    current_user_id = int(get_jwt_identity())
    friend_request = FriendRequest.query.get(request_id)

    if not friend_request:
        return jsonify({"message": "Invalid friend request"}), 400
    
    if friend_request.receiver_id != current_user_id:
        return jsonify({"message": "You cannot reject this friend request"}), 400

    db.session.delete(friend_request)
    db.session.commit()

    return jsonify({"message": "Friend request rejected!"}), 200

@app.route('/friends', methods=['GET'])
def friends():
    return render_template('friends.html')

@app.route('/friends/data', methods=['GET'])
@jwt_required()
def friends_data():
    current_user_id = int(get_jwt_identity())
    
    friendships = Friends.query.filter(
        (Friends.user1_id == current_user_id) | (Friends.user2_id == current_user_id)
    ).all()

    requests_json = [
        {
            "friend_id": friendship.user1_id if friendship.user1_id != current_user_id else friendship.user2_id,
            "friend_username": User.query.get(friendship.user1_id if friendship.user1_id != current_user_id else friendship.user2_id).username
        }
        for friendship in friendships
    ]

    return jsonify({"friends": requests_json, "status": "success"}), 200

@app.route('/chat/<int:friend_id>')
def chat(friend_id):
    return render_template('chat.html', friend_id=friend_id)

@app.route('/chat/data/<int:friend_id>', methods=['GET'])
@jwt_required()
def chat_data(friend_id):
    current_user_id = int(get_jwt_identity()) 

    friend = User.query.get(friend_id)
    if not friend:
        return jsonify({"message": "Friend not found"}), 404

    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.receiver_id == friend_id)) |
        ((Message.sender_id == friend_id) & (Message.receiver_id == current_user_id))
    ).order_by(Message.timestamp).all()

    message_data = []
    for msg in messages:
        message_data.append({
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "message": Message.decrypt_message(msg.content),
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({
        "friend_id": friend.id,
        "friend_username": friend.username,
        "messages": message_data
    }), 200

@socketio.on("send_message")
def handle_message(data):
    try:
        token = request.args.get("token")
        if not token:
            print("No token provided send")
            return

        decoded_token = decode_token(token)
        sender_id = int(decoded_token["sub"]) 

        receiver_id = data.get("receiver_id")
        message_content = data.get("message")

        if not receiver_id or not message_content:
            return jsonify({"message": "Receiver ID and message are required"}), 400

        sender = User.query.get(sender_id)
        if not sender:
            return jsonify({"message": "Sender not found"}), 404

        encrypted_message = Message.encrypt_message(message_content)
        new_message = Message(sender_id=sender_id, receiver_id=receiver_id, content=encrypted_message)
        db.session.add(new_message)
        db.session.commit()

        message_data = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "message": message_content,
            "sender_username": sender.username,
        }

        emit("receive_message", message_data, room=f"user_{receiver_id}")
        emit("receive_message", message_data, room=f"user_{sender_id}")

    except Exception as e:
        print(f"Error handling message: {e}")

@socketio.on('connect')
def handle_connect():
    token = request.args.get('token') 
    
    if not token:
        print("No token provided connect")
        disconnect()
        return

    try:
        decoded = decode_token(token)  
        user_id = int(decoded["sub"])  
        join_room(f"user_{user_id}")
        print(f"User {user_id} connected and joined room {user_id}")

    except Exception as e:
        print(f"JWT Error: {e}")
        disconnect()

@socketio.on("disconnect")
def handle_disconnect():
    try:
        token = request.args.get("token")
        if not token:
            print("No token provided disconnect")
            return

        decoded_token = decode_token(token)
        user_id = int(decoded_token["sub"])

        room = f"user_{user_id}"
        leave_room(room)
        print(f"User {user_id} disconnected from room: {room}")
    except Exception as e:
        print(f"Error on disconnect: {e}")

@app.route('/logout', methods=['POST'])
def logout():
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    socketio.run(app, debug=True)