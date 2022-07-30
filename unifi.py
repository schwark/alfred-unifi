import sys
import logging
from workflow import web
from Cookie import SimpleCookie
import json
import pyotp

log = logging.getLogger('pyunifi')
class UniFiClient(object):

    def __init__(self, base, username=None, password=None, site='default', state=None, unifios=None, mfa='', secret=''):
        self.base = base
        self.site = site
        self.username = username
        self.password = password
        self.mfa = mfa
        self.secret = secret
        self._set_type(unifios)
        self.session = True if state else False
        self.cookies = json.loads(state) if state else {}
        log.debug("cookies are :"+str(self.cookies))
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
            'base': {
                        'url': '/',
                        'ignore_response': True,
                        'global': True
            },
            'login': {
                        'global': True,
                        'data': {'username': lambda sf, **kwargs: sf.username, 'password': lambda sf, **kwargs: sf.password+('|'+sf.mfa if sf.mfa else '')}
            },
            'logout': {
                        'method': 'POST',
                        'global': True
            },
            'clients': {
                'url': '/stat/sta/'
            },
            'reservations': {
                'url': '/list/user/'
            },
            'networks': {
                'url': '/rest/networkconf/'
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
            'upgrade': {
                'url': '/cmd/devmgr/upgrade',
                'data': {
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
            },
            'fwrules': {
                'url': '/rest/firewallrule/'
            },
            'enable': {
                'url': lambda sf, **kwargs: '/rest/firewallrule/'+(kwargs['ruleid'] if 'ruleid' in kwargs else ''),
                'method': 'PUT',
                'data': {
                    'enabled': True
                }
            },
            'disable': {
                'url': lambda sf, **kwargs: '/rest/firewallrule/'+(kwargs['ruleid'] if 'ruleid' in kwargs else ''),
                'method': 'PUT',
                'data': {
                    'enabled': False
                }
            },
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

    def set_mfa(self, mfa):
        self.mfa = mfa

    def generate_mfa(self):
        if self.secret:
            totp = pyotp.TOTP(self.secret)
            self.mfa = totp.now()

    def _get_step_url(self, step, **kwargs):
        result = None
        step_metadata = self._get_step_metadata(step)
        if step_metadata and 'url' in step_metadata:
            url = step_metadata['url'](self, **kwargs) if callable(step_metadata['url']) else step_metadata['url']
            log.debug('using url : '+url)
            prefix = '/api/s/'
            if self.unifios:
                prefix = '/proxy/network'+prefix
            site_url = '' if ('global' in step_metadata and step_metadata['global']) else prefix+self.site
            result = self.base+site_url+url
            log.debug('using url : '+result)
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
        log.debug('kwargs are : '+str(kwargs))
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
            log.debug('setting csrf header to '+self.cookies['csrf_token'])
        if self.cookies:
            cookie_str = "; ".join([str(x)+"="+str(y) for x,y in self.cookies.items()])
            headers['Cookie'] = cookie_str
        request_params = {'url': self._get_step_url(step, **kwargs), 'method': method, 'allow_redirects': redirect, 'headers': headers, 'verify': False }
        if(data):
            if isinstance(data, dict):
                data = {k : v(self, **kwargs) if callable(v) else v for k, v in data.items()}
                log.debug(method+'ing data : '+str(data))
                request_params['data'] = json.dumps(data)
                headers['Content-Type'] = 'application/json'
            else:
                request_params['data'] = data
        log.debug("request is "+str(request_params))
        r = web.request(**request_params)
        if(r.status_code >= 200 and r.status_code <= 400 and 'set-cookie' in r.headers):
            cookies = SimpleCookie()
            cookies.load(r.headers['Set-Cookie'])
            for key, value in cookies.items():
                self.cookies[key] = value.value
        return r

    def _get_results(self, step, **kwargs):
        results = None
        tries = 0 # try a couple of times to resolve stale sessions as necessary
        while tries < 2:
            # refresh CSRF Token
            self._refresh_csrf()
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
                results = error
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
        request_metadata = self._get_step_metadata(operation)
        if (r.status_code >= 200 and r.status_code <= 400):
            log.debug('response code is '+str(r.status_code))
            csrf_token = r.headers['X-CSRF-Token']
            self.cookies['csrf_token'] = csrf_token
            response = r.json() if 'ignore_response' not in request_metadata or not request_metadata['ignore_response'] else None
            if response and 'meta' in response and 'rc' in response['meta']:
                if response['meta']['rc'] == 'ok':
                    log.debug(operation+': successful response is '+str(r))
                elif response['meta']['rc'] == 'error':
                    log.debug(operation+': failed request with error '+response['meta']['msg'])
                    if response['meta']['msg'] == 'api.err.LoginRequired':
                        log.debug(response['meta']['msg'])
                        self.session = False
                result = response['meta']['msg'] if 'msg' in response['meta'] else ''
        else:
            result = 'http.error.'+str(r.status_code)
            if 401 == r.status_code or 403 == r.status_code:
                self.session = False
            log.debug('API error code : '+result)
        return result

    def remove_cookie(self, cookie):
        if cookie in self.cookies:
            self.cookies[cookie] = None

    def get_save_state(self):
        result = ''
        if self.cookies:
            result = json.dumps(dict(self.cookies))
        return result
    
    def _refresh_csrf(self):
        # refresh CSRF Token
        self.cookies['csrf_token'] = None
        r = self._make_request(step='base')
        self._check_response(r, 'base')

    def login(self):
        # login
        self.generate_mfa()
        r = self._make_request(step='login')
        error = self._check_response(r, 'login')
        if(not error):
            self.session = True
        elif 'api.err.Invalid' == error:
            self.session = False
            log.debug('Invalid credentials')
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

    def get_networks(self):
        return self._get_results('networks')

    def get_reservations(self):
        return self._get_results('reservations')

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
    
    def get_fwrules(self):
        return self._get_results('fwrules')
    
    def enable_fwrule(self, ruleid):
        return self._get_results('fwrule_control', ruleid=ruleid, enable='true')

    def disable_fwrule(self, ruleid):
        return self._get_results('fwrule_control', ruleid=ruleid, enable='false')

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
    r = client.get_fwrules()
    #print json.dumps(r)
    client.logout()
