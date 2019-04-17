#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
#from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
#from itsdangerous import (TimedJSONWebSignatureSerializer
#                          as Serializer, BadSignature, SignatureExpired)

cer = os.path.join(os.path.dirname(__file__), 'ssl.crt')
key = os.path.join(os.path.dirname(__file__), 'ssl.key')

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
#auth = HTTPBasicAuth()

g_status=0
g_log=0
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

#    def generate_auth_token(self, expiration=600):
#        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
#        return s.dumps({'id': self.id})
#
#    @staticmethod
#    def verify_auth_token(token):
#        s = Serializer(app.config['SECRET_KEY'])
#        try:
#            data = s.loads(token)
#        except SignatureExpired:
#            return None    # valid token, but expired
#        except BadSignature:
#            return None    # invalid token
#        user = User.query.get(data['id'])
#        return user


#@auth.verify_password
#def verify_password(username_or_token, password):
#    # first try to authenticate by token
#    user = User.verify_auth_token(username_or_token)
#    if not user:
#        # try to authenticate with username/password
#        user = User.query.filter_by(username=username_or_token).first()
#        if not user or not user.verify_password(password):
#            return False
#    g.user = user
#    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/v1/auth-token',methods=['POST'])
def get_auth_token():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'errorCode': 10001, 'msg': "limit"}),403
    else:
        token = "axfasdf@@12"
        return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/')
def index():
    return "Hello World"

#@app.route('/api/resource')
#def get_resource():
#    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/v1/account/auth-access',methods=['POST'])
def get_resource():
    token = request.headers.get('Auth-Token')
    print token
    if cmp(token,'axfasdf@@12') == 0:
	    return jsonify({'s3':{'ak':"11111",'sk':'23423423','url':'http://sdf'}, "mirror":{'auth':'23423423','url':'http://sdf'}})
    else:    
	    return jsonify({'errorCode': 10001, 'msg': "limit"}),403

@app.route('/v1/basic-framework/<f_type>')
def framework_type(f_type):
	if cmp(f_type,"TRAIN") == 0:
	    return jsonify({'framework1':{'id':"1000",'name':'TensorFlow-1.13.1-python3.5'}})
	else:	
	    return jsonify({'errorCode': 10001, 'msg': "limit"}),403

@app.route('/v1/resource/<f_type>')
def resource_type(f_type):
	if cmp(f_type,"TRAIN") == 0:
	    return jsonify({'machine':{'id':"1000",'name':'cpu'}})
	else:	
	    return jsonify({'errorCode': 10001, 'msg': "limit"}),403


@app.route('/v1/train',methods=['POST'])
def start_train():
    token = request.headers.get('Auth-Token')
    job_name = request.json.get('name')
    print token
    if cmp(token,'axfasdf@@12') == 0:
            if job_name == "test_SDK": 
	    	return jsonify({'id':1001,"name":"testSDK_1","versionID":1001,"version":"1.1.1","output":"s3:/input/1.1.1"})
            else:
	    #return jsonify({'s3':{'ak':"11111",'sk':'23423423','url':'http://sdf'}, "mirror":{'auth':'23423423','url':'http://sdf'}})
	    	return jsonify({'id':1000,"name":"testSDK","versionID":1000,"version":"1.1.1","output":"s3:/input/1.1.1"})
    else:
	    return jsonify({'errorCode': 10001, 'msg': "limit"}),403

@app.route('/v1/train/version/<version_id>',methods=['GET','POST'])
def start_train_version(version_id):
    global g_status
    token = request.headers.get('Auth-Token')
    print token
    print version_id,type(version_id)
    if request.method == 'GET':
	    if cmp(token,'axfasdf@@12') == 0:
		if g_status < 5:
			g_status=g_status+1
			return jsonify({'id':100,"name":"testSDK_1","versionID":12345,"version":"1.1.1","status":"JOBSTAT_INIT"})
		elif g_status >= 5 and g_status < 10:
			g_status=g_status+1
			return jsonify({'id':100,"name":"testSDK_1","versionID":12345,"version":"1.1.1","status":"JOBSTAT_RUNNING"})
		elif g_status >=10 :
			g_status=0
			return jsonify({'id':100,"name":"testSDK_1","versionID":12345,"version":"1.1.1","status":"JOBSTAT_COMPLETED"})
    else:
	    if cmp(token,'axfasdf@@12') == 0:
		return jsonify({'id':1001,"name":"testSDK_1","versionID":12345,"version":"1.1.1","output":"s3:/input/1.1.1"})
	    else:
		return jsonify({'errorCode': 10001, 'msg': "limit"}),403

@app.route('/v1/train/version/log/<version_id>',methods=['GET','POST'])
def get_log(version_id):
    global g_log
    token = request.headers.get('Auth-Token')
    print token
    print version_id,type(version_id)
    if request.method == 'GET':
	    if cmp(token,'axfasdf@@12') == 0:
		if g_log < 4:
			g_log=g_log+1
			return jsonify({'log':">>>>>train runing,version is %s, nowtime %s"%(str(version_id),str(g_log))})
		elif g_log >=4 :
			g_log=0
			return jsonify({'log':">>>>>Train completed,version is %s, nowtime %s"%(str(version_id),str(g_log))})
    else:
	    if cmp(token,'axfasdf@@12') == 0:
		return jsonify({'id':1001,"name":"testSDK_1","versionID":12345,"version":"1.1.1","output":"s3:/input/1.1.1"})
	    else:
		return jsonify({'errorCode': 10001, 'msg': "limit"}),403


@app.route('/v1/train/version/output/<version_id>',methods=['GET','POST'])
def get_output(version_id):
    token = request.headers.get('Auth-Token')
    print token
    print version_id,type(version_id)
    if request.method == 'GET':
	    if cmp(token,'axfasdf@@12') == 0:
		return jsonify({'id':"1000","name":"testSDK","versionId":1000,"outputs":[{"name":"XXX.checkpoint","type":"file"},{"name":"evalute","type":"dir"}]})
    else:
	    if cmp(token,'axfasdf@@12') == 0:
		return jsonify({'id':1001,"name":"testSDK_1","versionID":12345,"version":"1.1.1","output":"s3:/input/1.1.1"})
	    else:
		return jsonify({'errorCode': 10001, 'msg': "limit"}),403



if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True,host="0.0.0.0",port=443,ssl_context=(cer,key))
    #app.run(debug=True,host="0.0.0.0",ssl_context=(cer,key))
    #app.run(debug=True,host="0.0.0.0",port=80)
