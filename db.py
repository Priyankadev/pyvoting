from pymongo import MongoClient
from flask import jsonify
import traceback
import json
import datetime
from bson import ObjectId


class Mdb:
    def __init__(self):
        # conn_str = "mongodb://admin:123@127.0.0.1:27017/admin"
        conn_str = "mongodb://voterixuser:voterixpass@ds251245.mlab.com:51245" \
                   "/voterix"

        # conn_str = 'mongodb://pmuser:pmpass@ds161742.mlab.com:61742/
        # projectmanager'
        client = MongoClient(conn_str)
        self.db = client['voterix']

#############################################
#                                           #
#       CHECK USER ALREADY EXIST OR NOT     #
#                                           #
#############################################
    def check_email(self, email):
        return self.db.user.find({'email': email}).count() > 0


#############################################
#                                           #
#            ADD USER IN DATABASE           #
#                                           #
#############################################
    def add_user(self, user, contact, email, password):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'name': user,
                'contact': contact,
                'email': email,
                'password': password,
                'creation_date': ts
            }
            self.db.user.insert(rec)

        except Exception as exp:
            print "add_user() :: Got exception: %s", exp
            print(traceback.format_exc())


#############################################
#                                           #
#           CHECK USER IN DATABASE          #
#                                           #
#############################################
    def user_exists(self, email):
        """
        function checks if a user with given email and password
        exists in database
        :param email: email of the user
        :param password: password of the user
        :return: True, if user exists,
                 False, otherwise
        """
        return self.db.user.find({'email': email}).count() > 0


#############################################
#                                           #
#        GET NAME ACCORDING TO EMAIL        #
#                                           #
#############################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
        return name

    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print 'password in db class', password
        return password


#############################################
#                                           #
#            USER SESSION IN DATABASE       #
#                                           #
#############################################
    def save_login_info(self, user_email, mac, ip, user_agent, type):
        LOGIN_TYPE = 'User Login'
        try:
            # ts = datetime.datetime.utcnow()
            # ts = datetime.datetime.now().strftime("%d-%m-%G  %H:%M:%S")
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")

            rec = {
                'user_id': user_email,
                'mac': mac,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': type,
                'timestamp': ts
            }

            self.db.user_session.insert(rec)
        except Exception as exp:
            print "save_login_info() :: Got exception: %s", exp
            print(traceback.format_exc())


#############################################
#                                           #
#            ADD ADMIN IN DATABASE          #
#                                           #
#############################################
    def add_admin(self, email, password):
        try:
            rec = {
                'email': email,
                'password': password
            }
            self.db.admin.insert(rec)
        except Exception as exp:
            print "add_admin() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#            ADD existing IN DATABASE       #
#                                           #
#############################################
    def admin_exists(self, email, password):

        return self.db.admin.find({'email': email, 'password': password}).\
                   count() > 0


#############################################
#                                           #
#                 GET USERS                 #
#                                           #
#############################################
    def get_users(self):
        collection = self.db["user"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

if __name__ == "__main__":
    mdb = Mdb()
    mdb.add_admin('tom@gmail.com', '123')
