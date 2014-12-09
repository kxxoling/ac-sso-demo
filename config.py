# coding: utf-8
from base64 import urlsafe_b64decode


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
