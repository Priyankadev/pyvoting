from flask import Flask, request, make_response, render_template, jsonify,\
    session, url_for, redirect, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
from flask_admin import Admin, BaseView, expose
import uuid
from uuid import getnode as get_mac
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
import time
from datetime import datetime, timedelta
import datetime
import traceback
import flask_login
import flask
import json
import jwt
import os
from db import Mdb
from werkzeug.utils import secure_filename
from wtforms.fields import SelectField
from eve import Eve

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'templates')

# app = Eve('voterix', template_folder=tmpl_dir)

app = Flask(__name__)

bcrypt = Bcrypt(app)
mdb = Mdb()


#############################################
#                                           #
#              WORKING  SESSION             #
#                                           #
#############################################
@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)
    flask.session.modified = True
    flask.g.user = flask_login.current_user
    # print'session in working'


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


#############################################
#                                           #
#        _id of mongodb record was not      #
#           getting JSON encoded, so        #
#           using this custom one           #
#                                           #
#############################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#           Login Manager                    #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})

        return f(*args, **kwargs)

    return decorated


############################################################################
#                                                                          #
#                                     USER PANNEL                          #
#                                                                          #
############################################################################
@app.route('/user')
@app.route('/')
def user():
    templateData = {'title': 'Login Page'}
    return render_template('user/index.html', session=session)


#############################################
#                  ADD USER                 #
#############################################
@app.route('/user/signup')
def signin():
    templateData = {'title': 'Signup Page'}
    return render_template('user/signup.html', session=session, **templateData)


@app.route("/user/add_user", methods=['POST'])
def add_user():
    try:
        user = request.form['user']
        contact = request.form['contact']
        email = request.form['email']
        password = request.form['password']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        check = mdb.check_email(email)
        if check:
            print"This Email Already Used"
            templateData = {'title': 'Signup Page'}
            return render_template('user/signup.html', **templateData)

        else:
            mdb.add_user(user, contact, email, pw_hash)
            print('User Is Added Successfully')

            return render_template('user/index.html', session=session)

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                 LOGIN USER                #
#############################################
@app.route('/user/login', methods=['POST'])
def login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print 'password in server, get from db class', pw_hash
            passw = bcrypt.check_password_hash(pw_hash, password)

            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                # flask_login.login_user(user, remember=False)
                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
                templateData = {'title': 'singin page'}
            else:
                return render_template('user/index.html', session=session)

        else:
            # Login Failed!
            return render_template('user/index.html', session=session)

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

        LOGIN_TYPE = 'User Login'
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr

        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    # return jsonify(ret)
    return render_template('user/index.html', session=session)


#############################################
#              SESSION LOGOUT               #
#############################################
@app.route('/clear')
def clearsession():
    try:
        LOGIN_TYPE = 'User Logout'
        sumSessionCounter()
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        return render_template('user/index.html', session=session)
    except Exception as exp:
        return 'clearsession() :: Got Exception: %s' % exp


#############################################
#                   Error 404               #
#############################################
@app.errorhandler(404)
def page_not_found(error):
    app.logger.error('Page not found: %s', (request.path))
    return render_template('admin/404.html'), 404


##############################################################################
#                                                                            #
#                                    ADMIN PANNEL                            #
#                                                                            #
##############################################################################
@app.route('/admin')
def admin():
    templateData = {'title': 'index page'}
    return render_template('admin/index.html', **templateData)


#############################################
#                 LOGIN ADMIN               #
#############################################
@app.route('/admin/admin_login', methods=['POST'])
def admin_login():
    ret = {'err': 0}
    try:

        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.admin_exists(email, password):
            name = mdb.get_name(email)
            session['name'] = name

            expiry = datetime.datetime.utcnow() + datetime.\
                timedelta(minutes=30)
            token = jwt.encode({'user': email, 'exp': expiry},
                               app.config['secretkey'], algorithm='HS256')
            ret['msg'] = 'Login successful'
            ret['err'] = 0
            ret['token'] = token.decode('UTF-8')
            return render_template('admin/index.html', session=session)
        else:
            templateData = {'title': 'singin page'}
            # Login Failed!
            return render_template('/admin/index.html', session=session)
            # return "Login faild"
            ret['msg'] = 'Login Failed'
            ret['err'] = 1

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
        # return jsonify(ret)
        return render_template('admin/index.html', session=session)


#############################################
#           ADMIN SESSION LOGOUT            #
#############################################
@app.route('/clear1')
def clearsession1():
    session.clear()
    return render_template('/admin/index.html', session=session)


#############################################
#                  GET USER                 #
#############################################
@app.route("/admin/get_users", methods=['GET'])
def get_users():
    users = mdb.get_users()
    templateData = {'title': 'Users', 'users': users}
    return render_template('admin/get_users.html', session=session, **templateData)


#############################################
#                  GET USER                 #
#############################################
@app.route("/admin/create_survey", methods=['GET'])
def create_survey():
    templateData = {'title': 'Create Survey Page'}
    return render_template('admin/create_survey.html', session=session, **templateData)


#############################################
#                CREATE SURVEY              #
#############################################
@app.route("/user/save_survey", methods=['POST'])
def save_survey():
    try:
        question = request.form['question']
        mdb.save_survey(question)
        print('Added Successfully')
        return render_template('admin/save_survey.html', session=session)

    except Exception as exp:
        print('save_survey() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                GET SURVEY                 #
#############################################
@app.route("/admin/get_all_survey", methods=['GET'])
def get_all_survey():
    surveys = mdb.get_all_surveys()
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('admin/get_surveys.html', session=session, **templateData)


#############################################
#                GET SURVEY                 #
#############################################
@app.route("/user/get_surveys", methods=['GET'])
def get_surveys():
    surveys = mdb.get_surveys()
    # print'==============', surveys
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('user/get_survey.html', session=session, **templateData)


#############################################
#               SAVE RESPONSE               #
#############################################
@app.route('/user/save_response', methods=['POST'])
def save_response():
    response = {}
    try:
        question = request.form['question']
        answer = request.form['answer']
        ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
        email = session['email']

        response['question'] = question
        response['answer'] = answer
        response['TimeStamp'] = ts
        response['email'] = email

        check = mdb.check_question(question, email)

        if check:

            mdb.update_response(response)
            # return render_template('user/get_survey.html', session=session)

        else:
            mdb.save_response(response)
        return render_template('user/save_response.html', session=session)

    except Exception as exp:
        print('save_response() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                GET SURVEY                 #
#############################################
@app.route("/admin/get_response", methods=['GET'])
def get_response():
    responses = mdb.get_responses()
    templateData = {'title': 'Responses', 'responses': responses}
    return render_template('admin/get_responses.html', session=session, **templateData)


@app.route('/user/graph_chart')
def graph_chart():
    templateData = {'title': 'Graph page'}
    return render_template('user/graph_chart.html', **templateData)


#################
#               #
#   API         #
#               #
#################
@app.route('/api_get_response')
def api_get_response():
    result = mdb.get_responses()
    print '--------', result
    ret = []
    for data in result:
        ret.append(data)
    print '', ret
    return JSONEncoder().encode({'data':ret})



#############################################
#                                           #
#                  MAIN SERVER              #
#                                           #
#############################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
