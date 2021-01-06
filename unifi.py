import sys
import logging
import requests
import json

from requests.sessions import RequestsCookieJar

logger = logging.getLogger('pyunifi')

class UniFiClient(object):

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

    _meta = {
        'common': {
            'check': {
                        'url': '/',
                        'method': 'POST',
                        'redirect': False,
                        'global': True
            },
            'login': {
                        'global': True,
                        'data': {'username': lambda sf, **kwargs: sf.username, 'password': lambda sf, **kwargs: sf.password}
            },
            'logout': {
                        'method': 'POST',
                        'global': True
            },
            'clients': {
                'url': '/stat/sta/'
            },
            'client': {
                'url': lambda sf, **kwargs: '/stat/sta/'+(kwargs['mac'] if 'mac' in kwargs else '')
            },
            'devices': {
                'url': '/stat/device/'
            },
            'device': {
                'url': lambda sf, **kwargs: '/stat/device/'+(kwargs['mac'] if 'mac' in kwargs else '')
            },
            'reboot': {
                'url': '/cmd/devmgr',
                'data': {
                    'cmd': 'restart',
                    'mac': lambda sf, **kwargs: (kwargs['mac'] if 'mac' in kwargs else '')
                }
            },
            'radius_acct': {
                'url': lambda sf, **kwargs: '/rest/account/'+(kwargs['mac'] if 'mac' in kwargs else '')
            },
            'radius_accts': {
                'url': '/rest/account'
            },
            'reconnect': {
                'url': '/cmd/stamgr',
                'data': {
                    'cmd': 'kick-sta',
                    'mac': lambda sf, **kwargs: (kwargs['mac'] if 'mac' in kwargs else '')
                }
            },
            'block': {
                'url': '/cmd/stamgr',
                'data': {
                    'cmd': 'block-sta',
                    'mac': lambda sf, **kwargs: (kwargs['mac'] if 'mac' in kwargs else '')
                }
            },
            'unblock': {
                'url': '/cmd/stamgr',
                'data': {
                    'cmd': 'unblock-sta',
                    'mac': lambda sf, **kwargs: (kwargs['mac'] if 'mac' in kwargs else '')
                }
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

    def _get_step_url(self, step, **kwargs):
        result = None
        step_metadata = self._get_step_metadata(step)
        if step_metadata and 'url' in step_metadata:
            url = step_metadata['url'](self, **kwargs) if callable(step_metadata['url']) else step_metadata['url']
            logger.debug('using url : '+url)
            site_url = '' if ('global' in step_metadata and step_metadata['global']) else '/api/s/'+self.site
            result = self.base+site_url+url
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

    def _make_request(self, step, **kwargs):
        request_metadata = self._get_step_metadata(step)
        logger.debug('kwargs are : '+str(kwargs))
        data = None
        if not request_metadata:
            return None
        if 'data' in request_metadata:
            data = request_metadata['data']
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
        request_params = {'url': self._get_step_url(step, **kwargs), 'method': method, 'cookies': self.cookies, 'allow_redirects': redirect, 'verify': False, 'headers': headers }
        if(data):
            if isinstance(data, dict):
                data = {k : v(self, **kwargs) if callable(v) else v for k, v in data.items()}
                logger.debug('posting data : '+str(data))
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

    def _get_results(self, step, **kwargs):
        results = None
        tries = 0 # try a couple of times to resolve stale sessions as necessary
        while tries < 2:
            if not self.session:
                self.login()
            r = self._make_request(step, **kwargs)
            error = self._check_response(r,  step)
            if(not error):
                tries = 2
                response = r.json()
                if 'data' in response:
                    results = response['data']
            else:
                tries += 1
        return results

    def _set_action(self, step, **kwargs):
        result = False
        tries = 0 # try a couple of times to resolve stale sessions as necessary
        while tries < 2:
            if not self.session:
                self.login()
            r = self._make_request(step, **kwargs)
            result = self._check_response(r,  step)
            if(not result):
                result = True
                tries = 2
            else:
                result = False
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
        r = self._make_request(step='login')
        error = self._check_response(r, 'login')
        if(not error):
            self.session = True
        elif 'api.err.Invalid' == error:
            self.session = False
            logger.debug('Invalid credentials')
        return error

    def logout(self):
        r = self._make_request(step='logout')
        error = self._check_response(r, 'logout')
        if(not error):
            self.session = False

    def get_results(self, step, **kwargs):
        return self._get_results(step, **kwargs)

    def get_devices(self):
        return self._get_results('devices')

    def get_clients(self):
        return self._get_results('clients')

    def get_device(self, mac):
        return self._get_results('device', mac=mac)

    def restart_device(self, mac):
        return self._get_results('restart_device', mac=mac)

    def get_client(self, mac):
        return self._get_results('client', mac=mac)

    def block_client(self, mac):
        return self._get_results('block_client', mac=mac)

    def unblock_client(self, mac):
        return self._get_results('unblock_client', mac=mac)

    def reconnect_client(self, mac):
        return self._get_results('reconnect_client', mac=mac)

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
            'name': lambda sf, **kwargs: kwargs['name'] if 'name' in kwargs else '',
            'x_password': password,
            'tunnel_type': tunnel_type,
            'tunnel_medium_type': tunnel_medium_type,
            'vlan': lambda sf, **kwargs: int(kwargs['vlan']) if 'vlan' in kwargs else 0
        }
        return self._set_action('radius_acct', data=data)

    def get(self, which, **kwargs):
        return self._get_results(which, **kwargs)

    def set(self, which, **kwargs):
        return self._set_action(which, **kwargs)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = UniFiClient('https://'+sys.argv[1]+':8443', username=sys.argv[2], password=sys.argv[3])
    r = client.get_device(sys.argv[4])
    #print json.dumps(r)
    client.logout()
