import sys
import logging
import requests
import json

from requests.sessions import RequestsCookieJar

logger = logging.getLogger('pyunifi')

class UniFiClient(object):

    _meta = {
        'common': {
            'check': {
                        'url': '/',
                        'method': 'POST',
                        'redirect': False,
                        'global': True
            },
            'login': {
                        'global': True
            },
            'logout': {
                        'method': 'POST',
                        'global': True
            },
            'clients': {
                'url': '/stat/sta/'
            },
            'client': {
                'url': '/stat/sta/',
                'ext': 'mac'
            },
            'devices': {
                'url': '/stat/device/'
            },
            'device': {
                'url': '/stat/device/',
                'ext': 'mac'
            },
            'radius_acct': {
                'url': '/rest/account'
            },
            'radius_accts': {
                'url': '/rest/account'
            }
        },
        'ubnt': {
            'login': {
                        'url': '/api/login',
            },
            'logout': {
                        'url': '/api/logout',
            },
            'cookie': 'unifises'

        },
        'unifios': {
            'login': {
                    'url': '/api/auth/login',
            },
            'logout': {
                    'url': '/api/auth/logout',
            },
            'cookie': 'TOKEN'
        }
    }

    def __init__(self, base, username=None, password=None, site='default', state=None, unifios=None):
        self.base = base
        self.site = site
        self.username = username
        self.password = password
        self._set_type(unifios)
        self.session = True if state else False
        self.cookies = requests.cookies.cookiejar_from_dict(json.loads(state)) if state else RequestsCookieJar()
        if None == unifios:
            self._check_unifios()
        else:
            self._set_type(unifios=unifios)

    def _get_step_url(self, step, params=None):
        result = None
        step_metadata = self._get_step_metadata(step)
        if step_metadata and 'url' in step_metadata:
            site_url = '' if ('global' in step_metadata and step_metadata['global']) else '/api/s/'+self.site
            result = self.base+site_url+step_metadata['url']
            if 'ext' in step_metadata and params and step_metadata['ext'] in params:
                result += params[step_metadata['ext']]
        return result

    def _get_step_metadata(self, step):
        result = {}
        if step in self.metadata:
            result = self.metadata[step] 
        if step in self._meta['common']:
            result.update(self._meta['common'][step])
        return result

    def _set_type(self, unifios=False):
        self.unifios = unifios
        self.metadata = self._meta[('unifios' if unifios else 'ubnt')]

    def _make_request(self, step, data=None, params=None):
        request_metadata = self._get_step_metadata(step)
        if not request_metadata:
            return None
        if 'method' in request_metadata:
            method = request_metadata['method']
        else:
            method = 'GET' if not data else 'POST'
        if 'redirect' in request_metadata:
            redirect = request_metadata['redirect']
        else:
            redirect = True
        headers = {}
        if 'csrf_token' in self.cookies and self.cookies['csrf_token']:
            headers['X-CSRF-Token'] = self.cookies['csrf_token']
            logger.debug('setting csrf header to '+self.cookies['csrf_token'])
        request_params = {'url': self._get_step_url(step, params), 'method': method, 'cookies': self.cookies, 'allow_redirects': redirect, 'verify': False, 'headers': headers }
        if(data):
            if isinstance(data, dict):
                request_params['json'] = data
            else:
                request_params['data'] = data
        r = requests.request(**request_params)
        if(r.status_code >= 200 and r.status_code <= 400):
            for cookie in r.cookies:
                if cookie.name in self.cookies:
                    del self.cookies[cookie.name]
                self.cookies.set_cookie(cookie)
        return r

    def _get_results(self, step, data=None, params=None):
        results = None
        tries = 0 # try a couple of times to resolve stale sessions as necessary
        while tries < 2:
            if not self.session:
                self.login()
            r = self._make_request(step, data, params)
            error = self._check_response(r,  step)
            if(not error):
                tries = 2
                response = r.json()
                if 'data' in response:
                    results = response['data']
            else:
                tries += 1
        return results

    def _set_action(self, step, data=None, params=None):
        result = None
        tries = 0 # try a couple of times to resolve stale sessions as necessary
        while tries < 2:
            if not self.session:
                self.login()
            r = self._make_request(step, data, params)
            result = self._check_response(r,  step)
            if(not result):
                tries = 2
            else:
                tries += 1
        return result

    def _check_unifios(self):
        r = self._make_request('check')
        if(r.status_code == 200):
            self._set_type(unifios=True)

    def _check_response(self, r, operation):
        result = ''
        if (r.status_code >= 200 and r.status_code <= 400):
            response = r.json()
            if 'meta' in response and 'rc' in response['meta']:
                if response['meta']['rc'] == 'ok':
                    logger.debug(operation+': successful response is '+str(r))
                elif response['meta']['rc'] == 'error':
                    logger.debug(operation+': failed request with error '+response['meta']['msg'])
                    if response['meta']['msg'] == 'api.err.LoginRequired':
                        self.session = False
                result = response['meta']['msg'] if 'msg' in response['meta'] else ''
        else:
            result = 'http.error.'+str(r.status_code)
        return result

    def get_save_state(self):
        result = ''
        if self.cookies:
            result = json.dumps(dict(self.cookies))
        return result

    def login(self):
        params = {'username': self.username, 'password': self.password}
        r = self._make_request(step='login', data=params)
        error = self._check_response(r, 'login')
        if(not error):
            self.session = True
        elif 'api.err.Invalid' == error:
            logger.debug('Invalid credentials')
        return error

    def logout(self):
        r = self._make_request(step='logout')
        error = self._check_response(r, 'logout')
        if(not error):
            self.session = False

    def get_devices(self):
        return self._get_results('devices')

    def get_clients(self):
        return self._get_results('clients')

    def get_device(self, mac):
        return self._get_results('device', params={'mac': mac})

    def get_client(self, mac):
        return self._get_results('client', params={'mac': mac})

    def get_radius_accts(self):
        return self._get_results('radius_accts')

    def set_radius_acct(self, name, password, tunnel_type, tunnel_medium_type, vlan=None):
        tunnel_type = int(tunnel_type)
        tunnel_medium_type = int(tunnel_medium_type)
        if tunnel_type < 1 or tunnel_type > 13:
            return "Invalid tunnel type"
        if tunnel_medium_type < 1 or tunnel_medium_type > 15:
            return "Invalid tunnel_medium_type"

        data = {
            'name': name,
            'x_password': password,
            'tunnel_type': tunnel_type,
            'tunnel_medium_type': tunnel_medium_type
        }
        if vlan:
            data['vlan'] = int(vlan)
        return self._set_action('radius_acct', data=data)

    def get(self, which, **kwargs):
        return self._get_results(which, **kwargs)

    def set(self, which, **kwargs):
        return self._set_action(which, **kwargs)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = UniFiClient('https://'+sys.argv[1]+':8443', username=sys.argv[2], password=sys.argv[3])
    print json.dumps(client.get_devices())
    client.logout()
