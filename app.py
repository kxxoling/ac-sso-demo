# -*- coding: utf-8 -*-
from functools import wraps

from flask import Flask, request, g, render_template, flash, redirect, abort

from config import APP_ID, SSO_HOST
from sign import ClientSign, TimeNotMatchError, SSOServerError, InvalidSign


app = Flask(__name__)


def sso_logined(func):
    """对应回调路由，如验证通过则执行相应程序"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        o = request.args.get('o', '')
        s = request.args.get('s', '')
        try:
            client_sign = ClientSign(o, s)
        except (TimeNotMatchError, SSOServerError, InvalidSign) as e:
            abort(401, e)

        g.client_sign = client_sign
        return func(*args, **kwargs)
    return wrapper


@app.before_request
def before_request():
    g.app_id = APP_ID
    g.sso_host = SSO_HOST


@app.route('/sso_sync')
def sso_sync():
    flash(u'数据同步完成：%s' % request.args.get('o'))
    return request.args.get('callback', '') + '({})'


@app.route('/sso_login')
@sso_logined
def sso_login():
    flash(u'SSO 用户 %s 已登录' % g.client_sign.sso_user_id)

    callback_url = request.args.get('callback', '')

    if not is_user_info_newest(g.client_sign.sso_user_id,
                               g.client_sign.user_info_id):
        return redirect(g.client_sign.signed_url(callback_url))

    return callback_url + '({})'


@app.route('/')
def index():
    return render_template('index.html')


def is_user_info_newest(user_id, user_info_id):
    """根据用户信息版本号判断数据库中用户信息是否需要更新"""
    flash(u'SSO 用户 %d 的个人资料版本号为 %d'
          % (user_id, user_info_id))
    return False


def get_user_id_by_sso_user_id(sso_user_id):
    """需要自己实现一个根据 SSO 服务器上用户 id 的函数"""
    return sso_user_id


if __name__ == '__main__':
    app.secret_key = "You won't guess this"
    app.run(debug=True)
