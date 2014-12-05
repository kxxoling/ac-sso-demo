import requests
from sso import HOST, APP_NAME, SSO_HOST, SYNC_URL, LOGIN_URL

SSO_REGISTER_URL = 'http://sso.tech2ipo.com/rpc/app.new'


def get_token():
    r = requests.get(SSO_REGISTER_URL, params=dict(
                     o='["%s","%s","%s","%s","%s"]'
                     % (APP_NAME, HOST, SSO_HOST, SYNC_URL, LOGIN_URL)))
    print r.url
    print r.text
    return r.text


if __name__ == '__main__':
    print get_token()
