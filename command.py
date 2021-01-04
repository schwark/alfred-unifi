# encoding: utf-8

import sys
import re
import argparse
import json
import os.path
from os import path
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

def get_item_icon(client, type):
    icon = 'generic'
    brand = client[type].lower().replace(' ','') if type in client else ''
    if(path.exists('icons/'+brand+'.png')):
        icon = brand
    elif brand and brand in icons:
        icon = icons[brand] 
    return 'icons/'+icon+'.png'

def save_state(wf, hub):
    if not hub:
        return
    state = hub.get_save_state()
    wf.save_password('unifi_state', state)

def refresh_session(wf, hub):
    hub.login()
    save_state(wf, hub)

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

def search_key_for_client(client):
    """Generate a string search key for a client"""
    elements = []
    name = client['name'] if client['name'] else client['hostname']
    elements.append(name)  # name of client
    elements.append(client['oui']) # brand of client
    elements.append(client['ip']) # ip of client
    return u' '.join(elements)

def search_key_for_device(device):
    """Generate a string search key for a device"""
    elements = []
    elements.append(device['name'])  # name of device
    elements.append(device['config_network']['ip'])  # ip of device
    return u' '.join(elements)

def search_key_for_radius(radius):
    """Generate a string search key for a radius user"""
    elements = []
    elements.append(radius['name'])  # name of radius user
    return u' '.join(elements)

def add_config_commands(wf, args, config_commands):
    word = args.query.lower().split(' ')[0] if args.query else ''
    config_command_list = wf.filter(word, config_commands.keys(), min_score=20, match_on=MATCH_SUBSTRING | MATCH_STARTSWITH | MATCH_ATOM)
    if config_command_list:
        for cmd in config_command_list:
            wf.add_item(config_commands[cmd]['title'],
                        config_commands[cmd]['subtitle'],
                        arg=config_commands[cmd]['args'],
                        autocomplete=config_commands[cmd]['autocomplete'],
                        icon=config_commands[cmd]['icon'],
                        valid=config_commands[cmd]['valid'])
    return config_command_list

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

def get_filtered_clients(query, clients, commands):
    result = wf.filter(query, clients, key=search_key_for_client, min_score=80, match_on=MATCH_SUBSTRING | MATCH_STARTSWITH | MATCH_ATOM)
    # check to see if the first one is an exact match - if yes, remove all the other results
    if result and query and 'name' in result[0] and result[0]['name'] and result[0]['name'].lower() == query.lower():
        result = result[0:1]
    return result

def get_filtered_devices(query, clients, commands):
    result = wf.filter(query, clients, key=search_key_for_device, min_score=80, match_on=MATCH_SUBSTRING | MATCH_STARTSWITH | MATCH_ATOM)
    # check to see if the first one is an exact match - if yes, remove all the other results
    if result and query and 'name' in result[0] and result[0]['name'] and result[0]['name'].lower() == query.lower():
        result = result[0:1]
    return result

def get_filtered_radius(query, clients, commands):
    result = wf.filter(query, clients, key=search_key_for_radius, min_score=80, match_on=MATCH_SUBSTRING | MATCH_STARTSWITH | MATCH_ATOM)
    # check to see if the first one is an exact match - if yes, remove all the other results
    if result and query and 'name' in result[0] and result[0]['name'] and result[0]['name'].lower() == query.lower():
        result = result[0:1]
    return result

def extract_category(args):
    category = None
    categories = ['c', 'd', 'r']
    if args.query:
        words = args.query.lower().split(' ')
        if words[0] in categories:
            category = words[0]
    return category

def extract_commands(args, clients, commands, filter_func):
    words = args.query.split() if args.query else []
    if clients:
        full_clients = filter_func(args.query,  clients, commands)
        minusone_clients = filter_func(' '.join(words[0:-1]),  clients, commands)
        minustwo_clients = filter_func(' '.join(words[0:-2]),  clients, commands)

        if 1 == len(minusone_clients) and (0 == len(full_clients) or (1 == len(full_clients) and full_clients[0]['mac'] == minusone_clients[0]['mac'])):
            extra_words = args.query.replace(minusone_clients[0]['label'],'').split()
            if extra_words:
                log.debug("extract_commands: setting command to "+extra_words[0])
                args.client_command = extra_words[0]
                args.query = minusone_clients[0]['label']
        if 1 == len(minustwo_clients) and 0 == len(full_clients) and 0 == len(minusone_clients):
            extra_words = args.query.replace(minustwo_clients[0]['label'],'').split()
            if extra_words:
                args.client_command = extra_words[0]
                args.query = minustwo_clients[0]['label']
                args.client_params = extra_words[1:]
        log.debug("extract_commands: "+str(args))
    return args

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

    words = args.query.split(' ') if args.query else []

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

    config_commands = {
        'update': {
            'title': 'Update clients and devices',
            'subtitle': 'Update the clients and devices from the controller',
            'autocomplete': 'update',
            'args': ' --update',
            'icon': ICON_SYNC,
            'valid': True
        },
        'unifios': {
            'title': 'Set controller to UniFi OS',
            'subtitle': 'Set the controller type to UniFiOS not the regular UniFi controller',
            'autocomplete': 'unifios',
            'args': ' --unifios',
            'icon': ICON_WEB,
            'valid': True
        },
        'upwd': {
            'title': 'Set username and password',
            'subtitle': 'Set controller username and password',
            'autocomplete': 'upwd',
            'args': ' --username '+(words[1] if len(words)>1 else '')+' --password '+(words[2] if len(words)>2 else ''),
            'icon': ICON_WEB,
            'valid': len(words) > 2
        },
        'site': {
            'title': 'Set site',
            'subtitle': 'Set site for controller commands',
            'autocomplete': 'site',
            'args': ' --site '+(words[1] if len(words)>1 else ''),
            'icon': ICON_WEB,
            'valid': len(words) > 1
        },
        'ip': {
            'title': 'Set controller IP',
            'subtitle': 'Set IP for controller commands',
            'autocomplete': 'ip',
            'args': ' --ip '+(words[1] if len(words)>1 else ''),
            'icon': ICON_WEB,
            'valid': len(words) > 1
        },
        'sort': {
            'title': 'Set sort order for clients',
            'subtitle': 'Set sort order for client commands',
            'autocomplete': 'sort',
            'args': ' --sort '+(words[1] if len(words)>1 else ''),
            'icon': ICON_WEB,
            'valid': len(words) > 1
        },
        'reinit': {
            'title': 'Reinitialize the workflow',
            'subtitle': 'CAUTION: this deletes all devices, clients and credentials...',
            'autocomplete': 'reinit',
            'args': ' --reinit',
            'icon': ICON_BURN,
            'valid': True
        },
        'workflow:update': {
            'title': 'Update the workflow',
            'subtitle': 'Updates workflow to latest github version',
            'autocomplete': 'workflow:update',
            'args': '',
            'icon': ICON_SYNC,
            'valid': True
        }
    }

    if(handle_config_commands(wf, args)):
        return 0

    # add config commands to filter
    add_config_commands(wf, args, config_commands)

    hub = get_hub(wf)

    # Update clients if that is passed in
    if args.update:  
        # update clients and devices
        clients = get_clients(wf, hub)
        devices = get_devices(wf, hub)
        radius = get_radius(wf, hub)
        wf.store_data('clients', clients)
        wf.store_data('devices', devices)
        wf.store_data('radius', radius)
        qnotify('UniFi', 'clients and devices updated')
        return 0  # 0 means script exited cleanly

   # handle any client or device commands there may be
    handle_client_commands(hub, args, client_commands)
    handle_device_commands(hub, args, device_commands)

 
    # update query post extraction
    query = args.query


    ####################################################################
    # View/filter clients or devices
    ####################################################################

    # Check for an update and if available add an item to results
    if wf.update_available:
        # Add a notification to top of Script Filter results
        wf.add_item('New version available',
            'Action this item to install the update',
            autocomplete='workflow:update',
            icon=ICON_INFO)


    if not clients or len(clients) < 1:
        wf.add_item('No clients...',
                    'Please use uf update - to update your UniFi clients.',
                    valid=False,
                    icon=ICON_WARNING)
        wf.send_feedback()
        return 0

    if not devices or len(devices) < 1:
        wf.add_item('No devices...',
                    'Please use uf update - to update your UniFi devices.',
                    valid=False,
                    icon=ICON_WARNING)
        wf.send_feedback()
        return 0

    # If script was passed a query, use it to filter posts
    if query:
        clients = get_filtered_clients(query, clients, client_commands)
        devices = get_filtered_devices(query, devices, device_commands)
        radius = get_filtered_radius(query, radius)

        items = [
            {
                'list': clients,
                'commands': client_commands,
                'type': 'client',
                'icon': 'oui',
                'id': 'mac',
                'filter': get_filtered_clients
            },
            {
                'list': devices,
                'commands': device_commands,
                'type': 'client',
                'icon': 'type',
                'id': 'mac',
                'filter': get_filtered_devices
            },
            {
                'list': radius,
                'commands': radius_commands,
                'type': 'radius',
                'icon': 'tunnel_type',
                'id': '_id',
                'filter': get_filtered_radius
            }
        ]

        for item in items:
            item_list = item['list']
            # since this i now sure to be a client/device query, fix args if there is a client/device command in there
            args = extract_commands(args, item['list'], item['commands'], item['filter'])

            if item_list:
                if 1 == len(item_list) and (not args[item['type']+'_command'] or args[item['type']+'_command'] not in item['commands']):
                    # Single client only, no command or not complete command yet so populate with all the commands
                    single = item_list[0]
                    cmd_list = list(filter(lambda x: x.startswith(args[item['type']+'_command']), item['commands']))
                    log.debug('args.'+item['type']+'_command is '+args[item['type']+'_command'])
                    for command in cmd_list:
                        wf.add_item(title=single['name'],
                                subtitle='Turn '+single['name']+' '+command+' '+(' '.join(args[item['type']+'_params']) if args[item['type']+'_params'] else ''),
                                arg=' --'+item['type']+item['id']+' '+single[item['id']]+' --'+item['type']+'-command '+command+' --'+item['type']+'-params '+(' '.join(args[item['type']+'_params'])),
                                autocomplete=single['name']+' '+command,
                                valid='arguments' not in item['commands'][command] or args[item['type']+'_params'],
                                icon=get_item_icon(single, item['icon']))
                elif 1 == len(clients) and (args[item['type']+'_command'] and args[item['type']+'_command'] in item['commands'] and args[item['type']+'_command'] in command_params):
                    # single client and has command already - populate with params?
                    single = item_list[0]
                    param_list = command_params[args[item['type']+'_command']]['values'] if 'values' in command_params[args[item['type']+'_command']] else []
                    param_start = args[item['type']+'_params'][0] if args[item['type']+'_params'] else ''
                    param_list = list(filter(lambda x: x.startswith(param_start), param_list))
                    param_list.sort()
                    check_regex = False
                    if not param_list and command_params[args[item['type']+'_params']]['regex']:
                        param_list.append(args.client_params[0].lower())
                        check_regex = True
                    for param in param_list:
                        wf.add_item(title=single['name'],
                                subtitle='Turn '+single['name']+' '+args[item['type']+'_command']+' '+param,
                                arg=' --'+item['type']+item['id']+' '+single[item['id']]+' --'+item['type']+'-command '+args[item['type']+'_params']+' --'+item['type']+'-params '+param,
                                autocomplete=single['name']+' '+args[item['type']+'_command'],
                                valid=not check_regex or re.match(command_params[args[item['type']+'_command']]['regex'], param),
                                icon=get_item_icon(single, item['icon']))
                else:
                    # Loop through the returned clients and add an item for each to
                    # the list of results for Alfred
                    for single in item_list:
                        wf.add_item(title=single['name'],
                                subtitle='Turn '+single['name']+' '+args[item['type']+'_command']+' '+(' '.join(args[item['type']+'_params']) if args[item['type']+'_params'] else ''),
                                arg=' --'+item['type']+item['id']+' '+single[item['id']]+' --'+item['type']+'-command '+args[item['type']+'_command']+' --'+item['type']+'-params '+(' '.join(args.client_params)),
                                autocomplete=single['name'],
                                valid=args[item['type']+'_command'] in item['commands'],
                                icon=get_item_icon(single, item['icon']))

        # Send the results to Alfred as XML
        wf.send_feedback()
    save_state()
    return 0


if __name__ == u"__main__":
    wf = Workflow(update_settings={
        'github_slug': 'schwark/alfred-unifi'
    })
    log = wf.logger
    sys.exit(wf.run(main))
    