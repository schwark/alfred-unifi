# encoding: utf-8

import sys
import re
import argparse
from os import listdir, environ
from unifi import UniFiClient
from workflow.workflow import MATCH_ATOM, MATCH_STARTSWITH, MATCH_SUBSTRING, MATCH_ALL, MATCH_INITIALS, MATCH_CAPITALS, MATCH_INITIALS_STARTSWITH, MATCH_INITIALS_CONTAIN
from workflow import Workflow3, ICON_WEB, ICON_WARNING, ICON_BURN, ICON_ERROR, ICON_SWITCH, ICON_HOME, ICON_COLOR, ICON_INFO, ICON_SYNC, web, PasswordNotFound

log = None

def qnotify(title, text):
    log.debug("notifying..."+text)
    print(text)

def error(text):
    print(text)
    exit(0)

def get_notify_name(wf, args):
    type = args['command_type']
    #log.debug('type in notify is '+type)
    idkey = 'mac' if ('mac' in args and args['mac']) else '_id'
    name = ''
    items = wf.cached_data(type, max_age=0)
    #log.debug('items in notify is '+str(items))
    if items:
        item = next((x for x in items if args[idkey] == x[idkey]), None)
        name = item['name'] if 'name' in item else item['hostname']
        name = ' '.join(map(lambda x: x.capitalize(), re.split('[\.\s\-\,]+', name)))
    return name

def get_client(wf, client_mac):
    clients = wf.cached_data('client', max_age=0)
    return next((x for x in clients if client_mac == x['mac']), None)

def get_device(wf, device_mac):
    devices = wf.cached_data('device', max_age=0)
    return next((x for x in devices if device_mac == x['mac']), None)

def save_state(wf, hub):
    if not hub:
        return
    state = hub.get_save_state()
    wf.save_password('unifi_state', state)

def refresh_session(wf, hub):
    hub.login()
    save_state(wf, hub)

def get_icons():
    icons = {
        'devices': {},
        'categories': {},
        'brands': {},
        'types': {}
    }
    for key in icons.keys():
        for f in listdir('icons/'+key):
            name = f.split('.')[0]
            if not name:
                continue
            words = name.split('-')
            for word in words:
                icons[key][word] = 'icons/'+key+'/'+f
    #log.debug('icons are :')
    #log.debug(str(icons))
    return icons

def get_hub(wf):
    need_setup = False
    hub = None
    mfa = ''
    secret = ''
    try:
        username = wf.get_password('unifi_username')
        password = wf.get_password('unifi_password')
    except PasswordNotFound:  
        wf.add_item('No username or password found...',
                    'Please use uf upwd to set your controller username and password',
                    valid=False,
                    icon=ICON_ERROR)
        need_setup = True
    try:
        mfa = wf.get_password('unifi_mfa')        
    except Exception:
        pass        
    try:
        secret = wf.get_password('unifi_secret')        
    except Exception:
        pass        
    ip = wf.settings['unifi_ip'] if 'unifi_ip' in wf.settings else None
    if not ip:
        wf.add_item('No controller ip found...',
                    'Please use uf ip to set your controller ip',
                    valid=False,
                    icon=ICON_ERROR)
        need_setup = True
    try:
        state = wf.get_password('unifi_state')
    except PasswordNotFound:
        state = None
    site = wf.settings['unifi_site'] if 'unifi_site' in wf.settings else 'default'
    unifios = wf.settings['unifi_unifios'] if 'unifi_unifios' in wf.settings else False
    if need_setup:
        wf.send_feedback()
        exit(0)
    else:
        port = 8443
        if unifios:
            port = 443
        hub = UniFiClient('https://'+ip+':'+str(port), username, password, site, state, unifios, mfa, secret)
    return hub

def enhance_client(client, networks):
    if 'use_fixedip' in client and client['use_fixedip'] and 'fixed_ip' in client and 'ip' not in client:
        client['ip'] = client['fixed_ip']
        
    if 'network_id' in client:
        network = next(x for x in networks if x['_id'] == client['network_id'])
        client['network_domain'] = network['domain_name'] if network else 'home.arpa'
    else:
        log.debug("no network id in "+str(client))
        
    return client

def generate_dns_alias_conf(clients):
    dns_alias_text = ""
    for client in clients:
        ip = client['ip'] if 'ip' in client else None
        if ip:
            name = client['name'] if 'name' in client else client['hostname']
            if 'network_domain' in client:
                fqdn = name+'.'+client['network_domain']
                dns_alias_text += "host-record={},{},{}\n".format(fqdn,name,ip)

    log.debug(dns_alias_text)
    filename = environ.get('HOME')+'/Downloads/dns-alias.conf'
    with open(filename, 'w') as outfile:
        outfile.write(dns_alias_text)

def get_clients(wf, hub):
    """Retrieve all clients

    Returns a list of clients.

    """
    clients = hub.get_clients()
    reservations = hub.get_reservations()
    allclients = list({x['mac']:x for x in (reservations + clients) if 'ip' in x or 'fixed_ip' in x}.values())
    networks = hub.get_networks()
    
    return map(lambda x: enhance_client(x, networks), allclients)

def get_devices(wf, hub):
    """Retrieve all devices

    Returns a list of devices.

    """
    return hub.get_devices()

def get_radius(wf, hub):
    """Retrieve all radius users

    Returns a list of radius users.

    """
    return hub.get_radius_accts()

def get_fwrules(wf, hub):
    """Retrieve all firewall rules

    Returns a list of firewall rules.

    """
    return hub.get_fwrules()

def handle_commands(wf, hub, args, commands):
    if not args.command_type or (not args.mac and not args._id) or args.command_type not in commands or args.command not in commands[args.command_type]:
        return 
    command = commands[args.command_type][args.command]
        
    # eval all lambdas in arguments
    if 'arguments' in command and command['arguments']:
        for i, arg in command['arguments'].items():
            if callable(arg):
                command['arguments'][i] = arg()
                log.debug('evaled the argument '+i+' : '+str(command['arguments'][i]))
            elif isinstance(arg, dict):
                for key, value in arg.items():
                    if callable(value):
                        arg[key] = value()                

    result = hub.get_results(args.command, **(command['arguments'] if 'arguments' in command else {}))
    log.debug("type of result is "+str(type(result))+" and result is "+str(result))
    if not result or type(result) is not str:
        qnotify("UniFi", get_notify_name(wf, vars(args))+' '+args.command+'ed ')
    else:
        qnotify("UniFi", get_notify_name(wf, vars(args))+' '+args.command+' error: '+result)        
    return result

def get_name(item):
    result = ''
    if 'name' in item:
        result = item['name']
    elif 'hostname' in item:
        result = item['hostname']
    return result

def  beautify(name):
    if not name:
        return ''
    # split by camel case  if there are
    # words = re.findall(r'[A-Z](?:[a-z]+|[A-Z]*(?=[A-Z]|$))', name)
    # if not, split by separators
    # if len(words) < 2:
    words = re.split('[\s\.\-\,\+]+', name)
    return ' '.join(map(lambda x: x.capitalize(), words))

def get_item_icon(icons, item):
    type = get_item_type(item)
    field = {'client': 'oui', 'device': 'type', 'radius': 'tunnel_type', 'fwrule': 'ruleset'}[type]
    words = beautify(get_name(item)).lower().split(' ')
    words.reverse()
    if('client' == type):
        # try category icon first
        for word in words:
            if 'categories' in icons and word in icons['categories']:
                return icons['categories'][word]
        # try brand icon next
        brand = str(item[field]).lower().replace(' ','') if field in item else ''
        if 'brands' in icons and brand in icons['brands']:
            return icons['brands'][brand]
    if('device' == type):
        model = item[field].lower()
        if 'devices' in icons and model in icons['devices']:
            return icons['devices'][model]
    # try type icon last
    if 'types' in icons and type in icons['types']:
        return icons['types'][type]
    return 'icons/generic.png'

def get_item_type(item):
    if 'model' in item:
        return 'device'
    if 'x_password' in item:
        return 'radius'
    if 'ruleset' in item:
        return 'fwrule'
    return 'client'

def post_process_item(icons, item):
    #log.debug("post processing "+str(item))
    item['_display_name'] = beautify(get_name(item))
    item['_type'] = get_item_type(item)
    item['_icon'] = get_item_icon(icons, item)
    return item

def handle_update(wf, args, hub):
    # Update clients if that is passed in
    if args.update:  
        # update clients and devices
        icons = get_icons()
        clients = map(lambda x: post_process_item(icons, x), get_clients(wf, hub))
        devices = map(lambda x: post_process_item(icons, x), get_devices(wf, hub))
        radius = map(lambda x: post_process_item(icons, x), get_radius(wf, hub))
        fwrules = map(lambda x: post_process_item(icons, x), get_fwrules(wf, hub))
        if clients:
            wf.cache_data('client', clients)
            generate_dns_alias_conf(clients=clients)
        if devices:
            wf.cache_data('device', devices)
        if radius:
            wf.cache_data('radius', radius)
        if fwrules:
            wf.cache_data('fwrule', fwrules)
        if icons:
            wf.cache_data('icons', icons)
        if devices:
            qnotify('UniFi', 'clients and devices updated')
        else:
            qnotify('UniFi', 'clients and devices update failed')
        return True # 0 means script exited cleanly


def handle_config_commands(wf, args):
    result = False
    # Reinitialize if necessary
    if args.reinit:
        wf.reset()
        try:
            wf.delete_password('unifi_username')
            wf.delete_password('unifi_password')
            wf.delete_password('unifi_mfa')
            wf.delete_password('unifi_secret')
            wf.delete_password('unifi_state')
        except PasswordNotFound:
            None
        qnotify('UniFi', 'Workflow reinitialized')
        return True

    if args.unifios:
        log.debug('saving unifios '+str(args.unifios))
        wf.settings['unifi_unifios'] = args.unifios
        wf.settings.save()
        qnotify('UniFi', 'Controller is now UniFiOS')
        return True

    if args.ip:
        log.debug('saving ip'+args.ip)
        wf.settings['unifi_ip'] = args.ip
        wf.settings.save()
        qnotify('UniFi', 'Controller IP Saved')
        return True

    if args.site:
        log.debug('saving site '+args.site)
        wf.settings['unifi_site'] = args.site
        wf.settings.save()
        qnotify('UniFi', 'Controller Site Saved')
        return True

    if args.freq:
        log.debug('saving freq '+args.freq)
        wf.settings['unifi_freq'] = int(args.freq)
        wf.settings.save()
        qnotify('UniFi', 'Update Frequency Saved')
        return True

    if args.sort:
        log.debug('saving sort order '+args.sort)
        wf.settings['unifi_sort'] = args.sort
        wf.settings.save()
        qnotify('UniFi', 'Sort order Saved')
        return True

    # save username and password if that is passed in
    if args.username or args.password or args.mfa or args.secret:  
        log.debug("saving username and password ")
        # save the key
        if args.username:
           wf.save_password('unifi_username', args.username)
        if args.password:
            wf.save_password('unifi_password', args.password)
        if args.secret:
            wf.save_password('unifi_secret', args.secret)
        if args.mfa:
            wf.save_password('unifi_mfa', args.mfa)
            hub = get_hub(wf)
            hub.remove_cookie('csrf_token')
        qnotify('UniFi', 'Credentials Saved')
        return True  # 0 means script exited cleanly

def main(wf):
    # build argument parser to parse script args and collect their
    # values
    parser = argparse.ArgumentParser()
    # add an optional (nargs='?') --apikey argument and save its
    # value to 'apikey' (dest). This will be called from a separate "Run Script"
    # action with the API key
    parser.add_argument('--upwd', dest='upwd', nargs='?', default=None)
    parser.add_argument('--site', dest='site', nargs='?', default=None)
    parser.add_argument('--freq', dest='freq', nargs='?', default=None)
    parser.add_argument('--ip', dest='ip', nargs='?', default=None)
    parser.add_argument('--sort', dest='sort', nargs='?', default=None)
    parser.add_argument('--username', dest='username', nargs='?', default=None)
    parser.add_argument('--password', dest='password', nargs='?', default=None)
    parser.add_argument('--mfa', dest='mfa', nargs='?', default="")
    parser.add_argument('--secret', dest='secret', nargs='?', default="")
    # add an optional (nargs='?') --update argument and save its
    # value to 'apikey' (dest). This will be called from a separate "Run Script"
    # action with the API key
    parser.add_argument('--update', dest='update', action='store_true', default=False)
    parser.add_argument('--unifios', dest='unifios', action='store_true', default=False)
    # reinitialize 
    parser.add_argument('--reinit', dest='reinit', action='store_true', default=False)
    # client name, mac, command and any command params
    parser.add_argument('--mac', dest='mac', default=None)
    parser.add_argument('--command', dest='command', default='')
    parser.add_argument('--command-type', dest='command_type', default='client')
    parser.add_argument('--command-params', dest='command_params', nargs='*', default=[])

    parser.add_argument('--_id', dest='_id', default=None)

    # add an optional query and save it to 'query'
    parser.add_argument('query', nargs='?', default=None)
    # parse the script's arguments
    args = parser.parse_args(wf.args)
    log.debug("args are "+str(args))

    # list of commands
    commands =  {
        'client':     {
                            'reconnect': {
                                    'arguments': {
                                        'mac': lambda: args.mac
                                    }
                            }, 
                            'block': {
                                    'arguments': {
                                        'mac': lambda: args.mac
                                    }
                            },
                            'unblock': {
                                    'arguments': {
                                        'mac': lambda: args.mac
                                    }
                            }
                        },
        'device':     {
                            'reboot': {
                                    'arguments': {
                                        'mac': lambda: args.mac
                                    }
                            }, 
                            'upgrade': {
                                    'arguments': {
                                        'mac': lambda: args.mac
                                    }
                            }, 
                        },
        'radius':     {
                            'delete': {
                                    'arguments': {
                                        'mac': lambda: args._id
                                    }
                            }, 
                        },
        'fwrule':     {
                            'enable': {
                                    'arguments': {
                                        'ruleid': lambda: args._id
                                    }
                            }, 
                            'disable': {
                                    'arguments': {
                                        'ruleid': lambda: args._id
                                    }
                            }, 
                        },

    }

    if(not handle_config_commands(wf, args)):
        hub = get_hub(wf)
        # handle any cache updates
        handle_update(wf, args, hub)
        # handle any client or device commands there may be
        handle_commands(wf, hub, args, commands)
        save_state(wf, hub)
    return 0


if __name__ == u"__main__":
    wf = Workflow3(update_settings={
        'github_slug': 'schwark/alfred-unifi'
    })
    log = wf.logger
    sys.exit(wf.run(main))
    