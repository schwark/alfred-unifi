# encoding: utf-8

from filter import beautify, get_name
import sys
import re
import argparse
import json
import os.path
from os import path, listdir
from unifi import UniFiClient
from workflow.workflow import MATCH_ATOM, MATCH_STARTSWITH, MATCH_SUBSTRING, MATCH_ALL, MATCH_INITIALS, MATCH_CAPITALS, MATCH_INITIALS_STARTSWITH, MATCH_INITIALS_CONTAIN
from workflow import Workflow3, ICON_WEB, ICON_WARNING, ICON_BURN, ICON_ERROR, ICON_SWITCH, ICON_HOME, ICON_COLOR, ICON_INFO, ICON_SYNC, web, PasswordNotFound

log = None
icons = {
}

def qnotify(title, text):
    print(text)

def error(text):
    print(text)
    exit(0)

def get_mac_name(mac, type):
    name = ''
    items = wf.cached_data(type, max_age=0)
    if items:
        item = next((x for x in items if mac == x['mac']), None)
        name = item['name'] if 'name' in item else item['hostname']
        name = ' '.join(map(lambda x: x.capitalize(), re.split('[\.\s\-\,]+', name)))
    return name

def get_client(wf, client_mac):
    clients = wf.cached_data('clients', max_age=0)
    return next((x for x in clients if client_mac == x['mac']), None)

def get_device(wf, device_mac):
    devices = wf.cached_data('devices', max_age=0)
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
    log.debug('icons are :')
    log.debug(str(icons))
    return icons

def get_hub(wf):
    need_setup = False
    hub = None
    try:
        username = wf.get_password('unifi_username')
        password = wf.get_password('unifi_password')
    except PasswordNotFound:  
        wf.add_item('No username or password found...',
                    'Please use uf upwd to set your controller username and password',
                    valid=False,
                    icon=ICON_ERROR)
        need_setup = True
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
        hub = UniFiClient('https://'+ip+':8443', username, password, site, state, unifios)
    return hub

def get_clients(wf, hub):
    """Retrieve all clients

    Returns a list of clients.

    """
    return hub.get_clients()

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

def handle_commands(hub, args, commands):
    if not args.command_type or not args.mac or args.command_type not in commands or args.command not in commands[args.command_type]:
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
    if None != result:
        qnotify("UniFi", get_mac_name(args.mac, args.command_type)+' '+args.command+'ed ')
    return result

def handle_update(wf, args, hub):
    # Update clients if that is passed in
    if args.update:  
        # update clients and devices
        clients = get_clients(wf, hub)
        devices = get_devices(wf, hub)
        radius = get_radius(wf, hub)
        icons = get_icons()
        wf.cache_data('client', clients)
        wf.cache_data('device', devices)
        wf.cache_data('radius', radius)
        wf.cache_data('icons', icons)
        qnotify('UniFi', 'clients and devices updated')
        return True # 0 means script exited cleanly


def handle_config_commands(wf, args):
    result = False
    # Reinitialize if necessary
    if args.reinit:
        wf.reset()
        wf.delete_password('unifi_username')
        wf.delete_password('unifi_password')
        wf.delete_password('unifi_state')
        qnotify('UniFi', 'Workflow reinitialized')
        return True

    if args.unifios:
        log.debug('saving unifios '+args.unifios)
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
    if args.username or args.password:  
        log.debug("saving username and password "+args.username)
        # save the key
        wf.save_password('unifi_username', args.username)
        wf.save_password('unifi_password', args.password)
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

    }

    if(not handle_config_commands(wf, args)):
        hub = get_hub(wf)
        # handle any cache updates
        handle_update(wf, args, hub)
        # handle any client or device commands there may be
        handle_commands(hub, args, commands)
        save_state(wf, hub)

    return 0


if __name__ == u"__main__":
    wf = Workflow3(update_settings={
        'github_slug': 'schwark/alfred-unifi'
    })
    log = wf.logger
    sys.exit(wf.run(main))
    