# encoding: utf-8

import sys
import re
import argparse
import json
import os.path
from os import path, listdir
from unifi import UniFiClient
from workflow.workflow import MATCH_ATOM, MATCH_STARTSWITH, MATCH_SUBSTRING, MATCH_ALL, MATCH_INITIALS, MATCH_CAPITALS, MATCH_INITIALS_STARTSWITH, MATCH_INITIALS_CONTAIN
from workflow import Workflow, ICON_WEB, ICON_WARNING, ICON_BURN, ICON_ERROR, ICON_SWITCH, ICON_HOME, ICON_COLOR, ICON_INFO, ICON_SYNC, web, PasswordNotFound

log = None
icons = {
}

def qnotify(title, text):
    print(text)

def error(text):
    print(text)
    exit(0)

def get_client(wf, client_mac):
    clients = wf.stored_data('clients')
    return next((x for x in clients if client_mac == x['mac']), None)

def get_device(wf, device_mac):
    devices = wf.stored_data('devices')
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
        'devices': {

        },
        'categories': {

        },
        'brands': {

        },
        'types': {

        }
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
        refresh_session(wf, hub)
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

def handle_client_commands(hub, args, commands):
    if not args.client_mac or args.client_command not in commands.keys():
        return 
    command = commands[args.client_command]

    client = get_client(args.client_mac)
    client_name = client['label']
    capabilities = get_client_capabilities(client)
    if command['capability'] not in capabilities:
        error('Unsupported command for client')
        
    # eval all lambdas in arguments
    if 'arguments' in command and command['arguments']:
        for i, arg in enumerate(command['arguments']):
            if callable(arg):
                command['arguments'][i] = arg()
            elif isinstance(arg, dict):
                for key, value in arg.items():
                    if callable(value):
                        arg[key] = value()                

    data = {'commands': [command]}
    log.debug("Executing Switch Command: "+client_name+" "+args.client_command)
    result = st_api(api_key,'clients/'+args.client_mac+'/commands', None, 'POST', data)
    result = (result and result['results']  and len(result['results']) > 0 and result['results'][0]['status'] and 'ACCEPTED' == result['results'][0]['status'])
    if result:
        qnotify("UniFi", client_name+" turned "+args.client_command+' '+(args.client_params[0] if args.client_params else ''))
    log.debug("Switch Command "+client_name+" "+args.client_command+" "+(args.client_params[0] if args.client_params else '')+' '+("succeeded" if result else "failed"))
    return result

def handle_device_commands(hub, args, commands):
    if not args.device_mac:
        return 
    device = get_device(args.device_mac)
    device_name = device['deviceName']
    log.debug("Executing device Command: "+device_name)
    result = st_api(api_key,'devices/'+args.device_mac+'/execute', None, 'POST')
    result = (result and result['status'] and 'success' == result['status'])
    if result:
        qnotify("UniFi", "Ran "+device_name)
    log.debug("device Command "+device_name+" "+("succeeded" if result else "failed"))
    return result

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
    # retrieve cached clients and devices
    clients = wf.stored_data('clients')
    devices = wf.stored_data('devices')
    radius = wf.stored_data('radius')    

    # build argument parser to parse script args and collect their
    # values
    parser = argparse.ArgumentParser()
    # add an optional (nargs='?') --apikey argument and save its
    # value to 'apikey' (dest). This will be called from a separate "Run Script"
    # action with the API key
    parser.add_argument('--upwd', dest='upwd', nargs='?', default=None)
    parser.add_argument('--site', dest='site', nargs='?', default=None)
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
    parser.add_argument('--client-mac', dest='client_mac', default=None)
    parser.add_argument('--client-command', dest='client_command', default='')
    parser.add_argument('--client-params', dest='client_params', nargs='*', default=[])
    # device name, mac, command and any command params
    parser.add_argument('--device-mac', dest='device_mac', default=None)
    parser.add_argument('--device-command', dest='device_command', default='')
    parser.add_argument('--device-params', dest='device_params', nargs='*', default=[])

    # add an optional query and save it to 'query'
    parser.add_argument('query', nargs='?', default=None)
    # parse the script's arguments
    args = parser.parse_args(wf.args)
    log.debug("args are "+str(args))

    # list of commands
    client_commands = {
        'reconnect': {
                'command': 'reconnect'
        }, 
        'block': {
                'command': 'block'
        },
        'unblock': {
                'command': 'unblock',
        }
    }

    device_commands = {
        'reboot': {
                'command': 'reboot'
        }, 
        'clients': {
                'command': 'clients'
        }
    }

    radius_commands = {
        'reboot': {
                'command': 'reboot'
        }, 
        'clients': {
                'command': 'clients'
        }
    }

    command_params = {
    }

    if(handle_config_commands(wf, args)):
        return 0

    hub = get_hub(wf)

    # Update clients if that is passed in
    if args.update:  
        # update clients and devices
        clients = get_clients(wf, hub)
        devices = get_devices(wf, hub)
        radius = get_radius(wf, hub)
        icons = get_icons()
        wf.store_data('clients', clients)
        wf.store_data('devices', devices)
        wf.store_data('radius', radius)
        wf.store_data('icons', icons)
        qnotify('UniFi', 'clients and devices updated')
        return 0  # 0 means script exited cleanly

   # handle any client or device commands there may be
    handle_client_commands(hub, args, client_commands)
    handle_device_commands(hub, args, device_commands)
    
    save_state()
    return 0


if __name__ == u"__main__":
    wf = Workflow(update_settings={
        'github_slug': 'schwark/alfred-unifi'
    })
    log = wf.logger
    sys.exit(wf.run(main))
    