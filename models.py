from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, String, Integer
from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from users import User_login

db = SQLAlchemy()


# database tables and configuration
class User(UserMixin, db.Model):
    id = Column('id', Integer, primary_key=True)
    username = Column('username', String(50), nullable=False)
    email = Column('email', String(60), nullable=False, unique=True)
    password = Column('password', String(100), nullable=False)
    SessionId = Column('SessionId', String(50), unique=True, default="asdsadadasd1232eqwdsadsa")
    friends = db.relationship('Friends', backref='friends')


# User friends 
class Friends(UserMixin, db.Model):
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    friend_name = Column('friend_name', String(50), nullable=True)
    added_by = Column('added_by', String(50), nullable=False)
    User_email = Column('user_email', String(50), db.ForeignKey('user.email'))

# Dummy message document
class messages(db.Model):
    id = Column('id', Integer, primary_key=True)
    username = Column('username', String(50), nullable=False)
    SessionId = Column('SessionId', String(50), unique=True, default="asdsadadasd1232eqwdsadsa")


# Creating rooms 
class Rooms(UserMixin, db.Model):
    room_id = Column('room_id', Integer, primary_key=True, autoincrement=True)
    room_name = Column('room_name', String(50), nullable=False, unique=False)
    created_by = Column('created_by', String(50), nullable=False)
    created_at = Column('created_at', String(40), nullable=False)


# room_members with room_name of the user
class Room_members(UserMixin, db.Model):
    member_id = Column('member_id', Integer, primary_key=True, autoincrement=True)
    member_name = Column('member_name', String(50), nullable=False, unique=False)
    room_name = Column('room_name', String(50), nullable=False, unique=False)
    added_by = Column('added_by', String(50), nullable=False)
    is_room_admin = Column('is_room_admin', String(10), nullable=False)
    added_at = Column('added_at', String(40), nullable=False)



#
class Storing_messages(UserMixin, db.Model):
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    sender_name = Column('sender_name', String(50), nullable=False)
    room_name = Column('room_name', String(50), nullable=False)
    message = Column('message', String(255), nullable=False)
    created_at = Column('created_at', String(20), nullable=False)


class Private_message(db.Model):
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    sender_name = Column('sender_name', String(50), nullable=False)
    message = Column('message', String(255), nullable=False)
    friend_to = Column('friend_to', String(50))
    created_at = Column('created_at', String(20), nullable=False)

# database operations
def save_user(username, email, password, sessionId):
    password_hash = generate_password_hash(password, method='sha256')
    user = User(username=username, email=email, password=password_hash, SessionId=sessionId)
    db.session.add(user)
    db.session.commit()
    return user


def get_test_user(username):
    return User.query.filter_by(username=username).first()


def get_test_email(email):
    return User.query.filter_by(email=email).first()

def get_user(username):
    user_data = User.query.filter_by(username=username).first()
    return User_login(user_data.id, user_data.username, user_data.email, user_data.password) if user_data else None


def save_rooms(room_name, created_by):
    room = Rooms(room_name=room_name, created_by=created_by, created_at=datetime.now())
    if room:
        db.session.add(room)
        db.session.commit()
        roomname = room_name
        return roomname
    else:
        return False


def add_room_member(room_name, usernames, added_by, is_room_admin):
    roommembers = Room_members(member_name=usernames, room_name=room_name, added_by=added_by,
                               added_at=datetime.now(), is_room_admin=is_room_admin)
    db.session.add(roommembers)
    db.session.commit()


def add_room_members(room_name, username, added_by):
    bulk = Room_members(member_name=username, room_name=room_name, added_by=added_by,
                        added_at=datetime.now(), is_room_admin=False)
    db.session.add(bulk)
    db.session.commit()


def is_room_member(member_name, room_name):
    isroommember = Room_members.query.filter_by(member_name=member_name, room_name=room_name).first()
    if isroommember:
        return isroommember
    else:
        return None


def get_room(room_name):
    room_names = Rooms.query.filter_by(room_name=room_name).first()
    if room_names:
        return room_names
    else:
        return None


def get_rooms_for_users(username):
    rooms = Room_members.query.filter_by(member_name=username)
    return rooms


def get_room_members(room_name):
    rooms = Room_members.query.filter_by(room_name=room_name)
    return rooms


def is_room_admin_1(room_name, member_name):
    return Room_members.query.filter_by(room_name=room_name, member_name=member_name, is_room_admin=True).first()


def updated_room(old_room_name, new_room_name):
    rooms = Rooms.query.filter_by(room_name=old_room_name).update({Rooms.room_name: new_room_name})
    if rooms:
        db.session.commit()
        return rooms
    else:
        return None


def update_members_room(old_members_room, new_members_room):
    old_member_room = Room_members.query.filter_by(room_name=old_members_room).update(
        {Room_members.room_name: new_members_room})
    if old_member_room:
        db.session.commit()
        return old_member_room
    else:
        return None


def updated_room_members(old_member_name, new_member_names):
    for new_names in new_member_names:
        return Room_members.query.filter_by(member_name=old_member_name).update({Room_members.member_name: new_names})


def remove_rooms(room_name):
    deleted_room = Rooms.query.filter_by(room_name=room_name).delete()
    if deleted_room:
        db.session.commit()
        Room_members.query.filter_by(room_name=room_name).delete()
        db.session.commit()
        Storing_messages.query.filter_by(room_name=room_name).delete()
        db.session.commit()
        return deleted_room
    else:
        return None


def update_session_id(email, sessionid):
    update = User.query.filter_by(email=email).update({User.SessionId: sessionid})
    if update:
        db.session.commit()
        return update
    else:
        return None


def return_only_username():
    return db.session.query(User.username)


def save_messages(username, room_name, message, created_at):
    message = Storing_messages(sender_name=username, room_name=room_name, message=message, created_at=created_at)
    if message:
        db.session.add(message)
        db.session.commit()
        return message
    else:
        return None


def get_messages(room_name):
    return Storing_messages.query.filter_by(room_name=room_name)


def save_private_message(message, sender_name, reciever_name,  created_at):
    message =  Private_message(message=message, sender_name=sender_name, friend_to=reciever_name, created_at=created_at)
    if message:
        db.session.add(message)
        db.session.commit()
        return message
    else:
        return None



def add_friends(friend_name, current_username, current_email):
    friends = Friends(friend_name=friend_name, added_by=current_username, User_email=current_email)
    if friends:
        db.session.add(friends)
        db.session.commit()
        return friends
    else:
        return None


def get_friends_list(current_username):
    friends_list =  Friends.query.filter_by(added_by=current_username).all()
    if friends_list:
        return friends_list
    else:
        return None


def get_authorized_messages(friend_name, current_username):
    return Friends.query.filter_by(friend_name=friend_name, added_by=current_username).all()
    



def get_private_messages(sender_name, friend_to):
    message = Private_message.query.filter_by(sender_name=sender_name, friend_to=friend_to).all()
    if message:
        return message
    else:
        return None