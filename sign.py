# coding: utf-8
import time
from json import dumps, loads
from hashlib import sha512
from urllib import urlencode
from base64 import urlsafe_b64decode, urlsafe_b64encode

from config import TOKEN, APP_ID, SSO_HOST


class ClientSign(object):
    def __init__(self, o, s):
        if not o:
            raise SSOServerError
        if not s:
            raise SSOServerError
        self.o = o
        self.sso = loads(o)
        user_info_id = self.sso.get('user_info_id')
        self.user_info_id = user_info_id and int(user_info_id) or 0
        self.session = self.sso.get('session')
        sso_user_id, self.sso_session = self.session.split('.', 2)
        self.sso_user_id = sso_user_id and int(sso_user_id) or 0
        timestamp, self.sign = s.split("|", 2)
        self.timestamp = int(timestamp)

    def verify(self):
        self._time_verify()
        signed_url = urlsafe_b64decode(str(self.sign) + "==")
        if signed_url != _sign(TOKEN, self.o, self.timestamp):
            raise InvalidSign

    def _time_verify(self):
        server_time = time.time()
        if abs(self.timestamp - server_time) > 300:
            raise TimeNotMatchError

    @property
    def signed_url(self, callback, o=None, path='/rpc/user.sync'):
        o = o or {}
        session_pair = self.session_decode()
        if session_pair:
            o['sso_id'] = session_pair[0]
        return sign_callback_url(self.sso_session, callback, o=o, path=path)

    def session_decode(self):
        """session 由 SSO 服务器设置，形如 9912642.pPPskgBpjJxyYXFk%22%2C
        该方法从 session 中取出 sso_user_id 和 sso_session，
        sso_user_id 即当前登录用户对应的 SSO 服务器 User_id
        sso_session 用于向 SSO 服务器发起请求
        """
        return int(self.sso_user_id), urlsafe_b64decode(str(self.sso_session))


def sign_callback_url(sso_session, callback, o=None, path='/rpc/user.sync'):
    """ 将参数编码在 URL 中，向 SSO 服务器发起请求"""
    o = o or {}
    if type(o) is basestring:
        o = loads(o)
    o['app_id'] = APP_ID
    o['info'] = o.get('info', "mail name ico sign phone")

    return "//%s%s?%s&callback=%s" % (
        SSO_HOST,
        path,
        _encode_url(str(sso_session)+TOKEN, o),
        callback
    )


def _encode_url(secret, o):
    """将时间时间戳、TOKEN等信息 encode 在 url 中"""
    o = dumps(o)
    timestamp = int(time.time())

    sign = urlsafe_b64encode(
        _sign(secret, o, timestamp)
    ).rstrip("=")
    s = "%d|%s" % (timestamp, sign)

    return urlencode(dict(
        s=s,
        o=o
    ))


def _sign(secret, o, timestamp):
    """使用 secret 对字典 o 和请求时间进行加密"""
    return sha512("%s|%s|%d" % (secret, str(o), timestamp)).digest()


class TimeNotMatchError(Exception):
    def __repr__(self):
        return "CLIENT TIME NOT MATCH SERVER TIME"


class SSOServerError(Exception):
    def __repr__(self):
        return "SSO Server Error"


class InvalidSign(Exception):
    def __repr__(self):
        return "Sign Not Invalid"


if __name__ == '__main__':
    pass
