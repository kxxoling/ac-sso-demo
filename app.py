# coding: utf-8
import time
import os
from functools import wraps
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha512
from urllib import urlencode
from json import dumps, loads

from flask import Flask, request, abort, g, render_template, flash, redirect


app = Flask(__name__)

HOST = 'b.dev'                              # App 域名
APP_NAME = 'test app'                       # App 名
SSO_HOST = 'sso.%s' % HOST                  # App 的 SSO 域名
SYNC_URL = 'http://%s/sso_sync' % HOST      # 数据同步接口
LOGIN_URL = 'http://%s/sso_login' % HOST    # 登录回调接口
APP_ID, TOKEN = [
    9912686,
    "QSxZWfYMl1PkWakayGuU7fEbR-2nSkz7tDZgZ-YkUiLjEGxZj5ENTU_S7GZp8k6o"
]
TOKEN = urlsafe_b64decode(TOKEN)


def sso_logined_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        o = request.args.get('o', '')
        s = request.args.get('s', '')
        if not s:
            abort(401, 's NOT FOUND')
        if not o:
            abort(500, 'SSO SERVER ERROR')

        timestamp, sign = s.split("|", 2)
        timestamp = int(timestamp)
        server_time = time.time()
        print server_time, timestamp
        if abs(timestamp - server_time) > 300:
            abort(401, "CLIENT TIME %s "
                  "NOT MATCH RPC SERVER TIME %d" % (time, server_time))

        if not ClientSign.verify(sign, TOKEN, o, timestamp):
            abort(401, "SIGN NOT MATCH")

        g.token = TOKEN
        sso = loads(o)
        g.sso = sso
        if sso.get('session'):
            sso_user_id, sso_session = sso.get('session').split('.', 2)
            g.sso_session = urlsafe_b64decode(str(sso_session))
            g.sso_user_id = int(sso_user_id)

        return func(*args, **kwargs)
    return wrapper


@app.before_request
def before_request():
    g.app_id = APP_ID
    g.sso_host = SSO_HOST


@app.route('/sso_sync')
@sso_logined_check
def sso_sync():
    flash(request.args.get('o'))
    return request.args.get('callback', '') + '({})'


@app.route('/sso_login')
@sso_logined_check
def sso_login():
    flash(u'SSO 用户 %s 已登录' % g.sso_user_id)
    flash(u'SSO 用户 %d 的个人资料版本号为 %d'
          % (g.sso_user_id, g.sso.get('user_info_id')))

    callback = request.args.get('callback', '')
    if not is_user_info_newest(g.sso_user_id, g.sso.get('user_info_id')):
        sso_sync_url = ClientSign.url_sign(g.sso_user_id, g.sso_session, callback)
        return redirect(sso_sync_url)

    return callback + '({})'


@app.route('/js/SSO/<file_name>')
def js_file(file_name):
    with open(os.path.join(os.getcwd(),
                           'static/js/SSO', file_name)) as f:
        fl = f.read()
    return fl


@app.route('/')
def index():
    return render_template('index.html')


def is_user_info_newest(user_id, user_info_id):
    return False


def get_user_id_by_sso_user_id(sso_user_id):
    return int(sso_user_id)


class ClientSign(object):
    @classmethod
    def verify(cls, sign, secret, o, time):
        sign = urlsafe_b64decode(str(sign) + "==")
        if sign == cls.sign(secret, o, time):
            return True

    @classmethod
    def sign(cls, secret, o, time):
        return sha512("%s|%s|%d" % (secret, str(o), time)).digest()

    @classmethod
    def url(cls, secret, o):
        o = dumps(o)
        timestamp = int(time.time())

        sign = urlsafe_b64encode(
            cls.sign(secret, o, timestamp)
        ).rstrip("=")
        s = "%d|%s" % (timestamp, sign)
        return urlencode(dict(
            s=s,
            o=o
        ))

    @classmethod
    def url_sign(cls, sso_user_id, sso_session, callback, o={}, path='user.sync'):
        o['sso_id'] = sso_user_id
        o['app_id'] = APP_ID
        o['info'] = "mail name ico sign phone"
        sso_session = str(sso_session)
        return "//%s/rpc/%s?%s&callback=%s" % (
            SSO_HOST,
            path,
            cls.url(sso_session+TOKEN, o),
            callback
        )


if __name__ == '__main__':
    app.secret_key = "You won't guess this"
    app.run(debug=True)
