from werkzeug.security import check_password_hash


class User_login:

    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

    def is_authenticated(self):
        return True

    def is_anonimous(self):
        return False

    def is_active(self):
        return True

    def get_id(self):
        return self.username

    def check_password(self, password_input):
        return check_password_hash(self.password, password_input)
