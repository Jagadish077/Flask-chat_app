from datetime import time, datetime
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_socketio import SocketIO, send, join_room, emit
from models import User, SQLAlchemy
from users import User_login
from models import save_user, get_user, save_rooms, add_room_member, get_room, get_rooms_for_users, \
    is_room_member, get_room_members, is_room_admin_1, updated_room, \
    update_members_room, get_test_user, remove_rooms, update_session_id, save_messages, \
    get_messages, save_private_message, get_private_messages, add_friends, get_friends_list, \
        get_test_email, get_authorized_messages

app = Flask(__name__)

# database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://///home/jagadish/Documents/Python/chat_app.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = "kill you"
socketio = SocketIO(app, cors_allowed_origins="*")

# login configuration
loginmanager = LoginManager(app)
loginmanager.init_app(app)
loginmanager.login_view = "login"
loginmanager.login_message = "Please Login to Access that page"
loginmanager.login_message_category = "danger"

users = {}


@loginmanager.user_loader
def load_user(id):
    return User.query.get(int(id))


# home page
@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('base.html')


# user login route
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        user = request.form['user_name']
        password_input = request.form['pass_word']
        if user and password_input is not None:

            if get_user(user):
                test_user_data = get_test_user(user)
                user_models = User_login(test_user_data.id, test_user_data.username, test_user_data.email,
                                         test_user_data.password)
                password = user_models.check_password(password_input)
                if password:
                    login_user(test_user_data)
                    # session['username'] = user_models.get_id()
                    flash("login successfull", "success")
                    return redirect(url_for('get_rooms'))
                else:
                    flash("password is incorrect", "danger")
            else:
                flash("Invalid Credintials", "danger")
        else:
            flash("username and password not met", "danger")

    return render_template('login.html')


# registering the user with username and password
@app.route('/sign_up', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        sessionid = request.form['sessionid']
        username = request.form['user_username']
        password = request.form['user_password']
        email = request.form['Email']

        user = get_user(username)
        if user is None:
            save_user(username, email, password, sessionid)
            flash("user successfully added", "success")

        else:
            flash("user already exist", "danger")
            # flash("user successfully saved", "success")

    return render_template('user_login.html')


# this is the chat page
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    return render_template('_chat_app.html', username=session.get("username"))


# creating rooms ....he must be logged in
@app.route('/create_room', methods=['GET', 'POST'])
@login_required
def create_room():
    if request.method == 'POST':
        room_name = request.form['room_name']
        if get_room(room_name):
            flash("Room already exist", "danger")
        else:
            roomid = save_rooms(room_name, current_user.username)
            add_room_member(room_name, current_user.username, current_user.username, is_room_admin=True)
            if roomid:
                return redirect(url_for('add_members', ))

    return render_template('_create_room.html')


# adding the room members with add_room_member and no duplicate member will be allowed to add
@app.route('/add_members', methods=['POST', 'GET'])
@login_required
def add_members():
    if request.method == 'POST':
        room_name = request.form['room_name']
        usernames1 = request.form['usernames']
        if get_room(room_name) and is_room_admin_1(room_name, current_user.username):
            if get_test_user(usernames1):
                    
                if is_room_member(usernames1, room_name) is None:
                    if usernames1 == current_user.username:
                        add_room_member(room_name, usernames1, current_user.username, is_room_admin=True)
                        return redirect(url_for('get_rooms'))
                    else:
                        add_room_member(room_name, usernames1, current_user.username, is_room_admin=False)
                        return redirect(url_for('get_rooms'))
                else:
                    flash(f"{usernames1} already in a room", "warning")
            else:
                flash(f"{usernames1} is not a registered member..Register first", "danger")
        else:
            flash("failed to add members", "danger")
    return render_template('add_room_member.html')


# all room will be displayed  and room displayed will of the logged in users and to which room he belongs to else he
# will be displayed with proper err message
@app.route('/get_rooms', methods=['GET', 'POST'])
@login_required
def get_rooms():
    if request.method == 'GET':
        rooms = get_rooms_for_users(current_user.username)
        return render_template('_get_rooms.html', rooms=rooms)
    else:
        flash("you are not a member of any room", "warning")
    return render_template('_get_rooms.html')


# displaying the rooms which he joined
@app.route('/view_room/<room_name>/', methods=['GET'])
@login_required
def view_room(room_name):
    room = get_room(room_name)
    if room and is_room_member(current_user.username, room_name):
        messages = get_messages(room_name)
        room_members = get_room_members(room_name)
        return render_template('_view_room.html', room=room, room_members=room_members, messages=messages)

    else:
        flash(f"You are not a member of this group {room_name} please go back ", "warning")
        return render_template('error.html')
        # return "room not found", 404


# updating the room and members
@app.route('/update_room_names/<room_name>/', methods=['GET', 'POST'])
@login_required
def update_room_names(room_name):
    rooms = get_room(room_name)
    member = get_room_members(room_name)
    if request.method == 'POST':
        new_room_name = request.form['new_room_name']
        if is_room_admin_1(room_name, session.get('username')):
            # new_members_name = request.form['new_members_name']
            if updated_room(room_name, new_room_name) and update_members_room(room_name, new_room_name):
                flash("successfully updated room name and members room names", "success")
                return redirect(url_for("get_rooms"))
            else:
                flash("failed to update members room name and room names", "danger")
        else:
            flash("your are not a admin of this group", "warning")
    return render_template('_edit_room.html', rooms=rooms, member=member)


# deleting a room and room members
@app.route('/delete_room', methods=['POST', 'GET'])
@login_required
def delete():
    if request.method == 'POST':
        room_name = request.form['room_name']
        if room_name and is_room_admin_1(room_name, current_user.username):
            remove_rooms(room_name)
            flash("rooms successfully deleted", "Danger")
            return redirect(url_for('get_rooms'))
        else:
            flash("failed to delete room", "secondary")
    return render_template('delete.html')


# adding friends for the private chat and friend must be registered before adding the friend
@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    if request.method == 'POST':
        friends_name = request.form['user_email']
        if friends_name is not None and get_test_email(friends_name):
            user_email = get_test_user(current_user.username)
            friends = add_friends(friends_name,current_user.username, user_email.email)
            if friends:
                flash(f"successfully added {friends_name} to friend list", "success")
                return redirect(url_for("private_chat"))
            else:
                flash(f"failed to add friend {friends_name} to friend list", "warning")
        else:
            flash(f"This {friends_name} is not a valid name", "danger")

    return render_template("_add_friends.html")



# this is a private message page
@app.route('/private_chat', methods=['GET', 'POST'])
@login_required
def private_chat():
    email = get_test_user(current_user.username)
    all_ids = get_friends_list(current_user.username)
    print(all_ids)
    if all_ids:   
        return render_template('private.html', user=users, all_names=all_ids)
    else:
        flash("your friends list is emprty ", "warning")
        return render_template('private.html')

@app.route('/chat_private/<name>/', methods=['GET', 'POST'])
@login_required
def chat_private(name):
    if get_authorized_messages(name, current_user.username):
        messages = get_private_messages(current_user.username, name)
        print(messages, name)
        return render_template('_chat_private.html', name=name, messages=messages)
    else:
        flash("something wend Wrong please go back to login page", "danger")


# this is a private message socket
@socketio.on('private_message')
def private_lol(msg):
    user_session = msg['username']
    message = msg['message']

    emit('new_private', message, room=user_session)


# this is a group message socket
@socketio.on('incoming-msg')
def on_message(data):
    """Broadcast messages"""
    rooms = get_room(data["room"])
    if rooms:
        users_rooms = get_room_members(rooms.room_name)
        if users_rooms:
            for members in users_rooms:
                msg = data["msg"]
                if members.member_name == current_user.username:
                    room = rooms.room_name
                    now = datetime.now()
                    time_stamp = now.strftime("%H:%M:%S")
                    message = save_messages(current_user.username, room, msg, time_stamp)
                    if message:
                        print("message saved")
                        print(time_stamp)
                        send({"username": current_user.username, "msg": msg, "time": time_stamp}, room=room)
                    else:
                        print("Something went wrong")
    else:
        return "message not sent"


# joining the rooms ...invoking joinroom function
@socketio.on('join')
def on_join(data):
    """User joins a room"""
    rooms = get_room(data["room"])
    if rooms:
        username = get_user(data["username"])
        room = rooms.room_name
        join_room(room)
        # Broadcast that new user has joined
        now = datetime.now()
        time_stamp = now.strftime("%H:%M:%S")
        send({"username": current_user.username, "msg": "has came to online", "time": time_stamp}, room=room)
        print('message got sent')


# private chat socket using session_ids
@socketio.on('username', namespace='/private')
def username(username):
    sessionid = get_test_email(username)
    if sessionid:
        update_session_id(sessionid.email, request.sid)
        users[sessionid.email] = sessionid.SessionId
        print('username added')
        print(users)
    else:
        print("no username found")


# sending the message to specific user
@socketio.on('private', namespace='/private')
def private(pyaload):
    username = get_test_email(pyaload['email'])
    if username:
        users1 = list()
        recipient_session = users[pyaload['email']]
        print("user removed")   
        message = pyaload['message']
        now = datetime.now()
        time_stamp = now.strftime("%H:%M:%S")
        save_private_message(message, current_user.email, pyaload['email'], time_stamp)
        emit('message', {"message": message, "username": current_user.email}, room=recipient_session)
    else:
        return "message not sent"


# logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("successfully logged out", "success")
    return redirect(url_for('login'))


if __name__ == "__main__":
    socketio.run(app, debug=True)
