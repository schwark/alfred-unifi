# encoding: utf-8

import sys
import re
import argparse
import json
from time import strftime, gmtime
import os.path
from os import path
from unifi import UniFiClient
from workflow.workflow import MATCH_ATOM, MATCH_STARTSWITH, MATCH_SUBSTRING, MATCH_ALL, MATCH_INITIALS, MATCH_CAPITALS, MATCH_INITIALS_STARTSWITH, MATCH_INITIALS_CONTAIN
from workflow import Workflow3, ICON_WEB, ICON_WARNING, ICON_BURN, ICON_ERROR, ICON_SWITCH, ICON_HOME, ICON_COLOR, ICON_INFO, ICON_SYNC, web, PasswordNotFound
from workflow.background import run_in_background, is_running

log = None

def error(text):
    print(text)
    exit(0)

def get_uptime(secs):
    if secs < 60:
        return str(secs)+' sec'
    if secs < 3600:
        return str(int(secs/60))+' min'
    if secs < 86400:
        return str(int(secs/60/60))+' hrs'
    if secs >= 86400:
        return str(int(secs/60/60/24))+' days'

def get_device_clients(wf, device):
    device_mac = device['mac']
    clients = wf.cached_data('client', max_age=0)
    result = filter(lambda x: ('ap_mac' in x and x['ap_mac'] == device_mac) or ('sw_mac' in x and x['sw_mac'] == device_mac), clients)
    return result

def get_item_subtitle(item, type, device_map):
    subtitle = u''

    if 'device' == type  and 'upgradable' in item and item['upgradable']:
        subtitle += '* '
    
    if 'ip' in item:
#        subtitle += u'  📨 '+item['ip']
        subtitle += item['ip']
#    if 'num_sta' in item:
#        subtitle += u'  👱 '+str(item['num_sta'])
#        subtitle += u'  • '+str(item['num_sta'])+' users'
    if 'device' == type:
#        if 'model' in item:
#            subtitle += u'  📠 '+item['model']
#            subtitle += u'  • '+item['model']
        if 'radio_table_stats' in item:
            for channel in item['radio_table_stats']:
                subtitle += u'  • ch '+str(channel['channel'])
                subtitle += u'  '+str(channel['tx_power'])+' dBm'
                subtitle += u'  '+str(channel['satisfaction'])+'%'
                subtitle += u'  '+str(channel['num_sta'])+' users'
        if 'uptime' in item:
    #            subtitle += u' 🕑 '+strftime('%jd %Hh %Mm %Ss',gmtime(item['uptime']))
            subtitle += u'  • '+get_uptime(item['uptime'])
    if 'client' == type:
#        if 'uptime' in item:
#            subtitle += u' 🕑 '+strftime('%jd %Hh %Mm %Ss',gmtime(item['uptime']))
#            subtitle += u'  • '+get_uptime(item['uptime'])
        if 'satisfaction' in item:
        #        subtitle += u'  👍🏼 '+str(item['satisfaction'])+'%'
            subtitle += u'  • '+str(item['satisfaction'])+'%'
        if 'network' in item:
#           subtitle += u'  🌐 '+item['network']
            subtitle += u'  • '+item['network']
        if 'ap_mac' in item and item['ap_mac'] in device_map:
#          subtitle += u'  📶 '+device_map[item['ap_mac']]['name']+' '+str(item['signal'])+' dBm'
            subtitle += u'  • '+device_map[item['ap_mac']]['name']
            subtitle += u' • ch '+str(item['channel'])
            subtitle += u' ▲'+str(int(item['tx_rate']/1000))
            subtitle += u' ▼'+str(int(item['rx_rate']/1000))
            subtitle += u' '+str(item['signal'])+' dBm'
            subtitle += u'  • '+('2.4G' if item['channel'] < 15 else '5G')
        elif 'sw_port' in item and item['sw_mac'] in device_map:
#            subtitle += u'  🔌 '+device_map[item['sw_mac']]['name']+' #'+str(item['sw_port'])
            subtitle += u'  • '+device_map[item['sw_mac']]['name']+' #'+str(item['sw_port'])
    if 'radius' == type:
        if 'vlan' in item:
            subtitle += u'  • vlan '+item['vlan']
        else:
            subtitle += u'  • no vlan'
        if 'tunnel_type' in item:
            subtitle += u'  •  tunnel type '+['','PPTP','L2F','L2TP','ATMP','VTP','AH','IP-IP','MIN-IP-IP','ESP','GRE','DVS','IP-Tunnel','VLAN'][item['tunnel_type']]
        if 'tunnel_medium_type' in item:
            subtitle += u'  •  tunnel medium '+['','IPv4','IPv6','NSAP','HDLC','BBN','802 all','E.163','E.164','F.69','X.121','IPX','AppleTalk','DECNet','Banyan','E.164-NSAP'][item['tunnel_medium_type']]

    return subtitle

def search_key_for_client(client):
    """Generate a string search key for a client"""
    elements = []
    if  'name' in client:
        elements.append(client['name'])  # name of client
    if  'hostname' in client:
        elements.append(client['hostname'])  # hostname of client
    if 'oui' in client:
        elements.append(client['oui']) # brand of client
    if 'ip' in client:
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

def add_prereq(wf, args):
    result = False
    word = args.query.lower().split(' ')[0] if args.query else ''
    # check IP
    ip = wf.settings['unifi_ip'] if 'unifi_ip' in wf.settings else None
    if not ip:
        if word != 'ip':
            wf.add_item('No controller ip found...',
                        'Please use uf ip to set your controller ip',
                        valid=False,
                        icon=ICON_ERROR)
        result = True
    # check username and password
    try:
        username = wf.get_password('unifi_username')
        password = wf.get_password('unifi_password')
    except PasswordNotFound:  
        if word != 'upwd':
            wf.add_item('No username or password found...',
                        'Please use uf upwd to set your controller username and password',
                        valid=False,
                        icon=ICON_ERROR)
        result = True
    # check devices
    clients = wf.stored_data('clients')
    devices = wf.stored_data('devices')
    if (not clients or not devices):
        if word != 'update':
            wf.add_item('No clients...',
                    'Please use uf update - to update your UniFi clients.',
                    valid=False,
                    icon=ICON_WARNING)
        result = True
    # Check for an update and if available add an item to results
    if wf.update_available:
        # Add a notification to top of Script Filter results
        wf.add_item('New version available',
            'Action this item to install the update',
            autocomplete='workflow:update',
            icon=ICON_INFO)
    return result

def add_config_commands(wf, query, config_commands):
    word = query.lower().split(' ')[0] if query else ''
    config_command_list = wf.filter(word, config_commands.keys(), min_score=80, match_on=MATCH_SUBSTRING | MATCH_STARTSWITH | MATCH_ATOM)
    if config_command_list:
        for cmd in config_command_list:
            wf.add_item(config_commands[cmd]['title'],
                        config_commands[cmd]['subtitle'],
                        arg=config_commands[cmd]['args'],
                        autocomplete=config_commands[cmd]['autocomplete'],
                        icon=config_commands[cmd]['icon'],
                        valid=config_commands[cmd]['valid'])
    return config_command_list

def get_filtered_items(query, items, search_func):
    result = wf.filter(query, items, key=search_func, min_score=80, match_on=MATCH_SUBSTRING | MATCH_STARTSWITH | MATCH_ATOM)
    # check to see if the first one is an exact match - if yes, remove all the other results
    name = result[0]['_display_name'] if result and len(result) > 0 else ''
    if name.lower() == query.lower():
        result = result[0:1]
    return result

def extract_commands(args, clients, filter_func):
    words = args.query.split() if args.query else []
    result = vars(args)
    if clients:
        full_clients = get_filtered_items(args.query,  clients, filter_func)
        minusone_clients = get_filtered_items(' '.join(words[0:-1]),  clients, filter_func)
        minustwo_clients = get_filtered_items(' '.join(words[0:-2]),  clients, filter_func)

        if 1 == len(minusone_clients) and (0 == len(full_clients) or (1 == len(full_clients) and full_clients[0]['mac'] == minusone_clients[0]['mac'])):
            name = minusone_clients[0]['_display_name']
            extra_words = args.query.replace(name,'').split()
            if extra_words:
                log.debug("extract_commands: setting command to "+extra_words[0])
                result['command'] = extra_words[0]
                result['query'] = name
        if 1 == len(minustwo_clients) and 0 == len(full_clients) and 0 == len(minusone_clients):
            name = minustwo_clients[0]['_display_name']
            extra_words = args.query.replace(name,'').split()
            if extra_words:
                result['command'] = extra_words[0]
                result['query'] = name
                result['params'] = extra_words[1:]
        log.debug("extract_commands: "+str(result))
    return result

def get_device_map(devices):
    return { x['mac']: x for x in devices }

def main(wf):
    # build argument parser to parse script args and collect their
    # values
    parser = argparse.ArgumentParser()
    # add an optional query and save it to 'query'
    parser.add_argument('query', nargs='?', default=None)
    # parse the script's arguments
    args = parser.parse_args(wf.args)
    log.debug("args are "+str(args))

    # update query post extraction
    query = args.query.lower() if args.query else ''
    words = query.split(' ') if query else []

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
        'upgrade': {
                'command': 'upgrade'
        }, 
        'reboot': {
                'command': 'reboot'
        }, 
        'clients': {
                'command': 'clients',
                'arguments': ['dummy']
        }
    }

    radius_commands = {
        'delete': {
                'command': 'delete'
        }, 
    }

    command_params = {
        'clients': {'dummy':'dummy'}
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
        'freq': {
            'title': 'Set device and client update frequency',
            'subtitle': 'Every (x) seconds, the clients and stats will be updated',
            'autocomplete': 'freq',
            'args': ' --freq '+(words[1] if len(words)>1 else ''),
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


    # add config commands to filter
    add_config_commands(wf, query, config_commands)
    if(add_prereq(wf, args)):
        wf.send_feedback()
        return 0
 
    freq = int(wf.settings['unifi_freq']) if 'unifi_freq' in wf.settings else 86400
    # Is cache over 1 hour old or non-existent?
    if not wf.cached_data_fresh('device', freq):
        run_in_background('update',
                        ['/usr/bin/python',
                        wf.workflowfile('command.py'),
                        '--update'])

    if is_running('update'):
        # Tell Alfred to run the script again every 0.5 seconds
        # until the `update` job is complete (and Alfred is
        # showing results based on the newly-retrieved data)
        wf.rerun = 0.5
        # Add a notification if the script is running
        wf.add_item('Updating clients and devices...', icon=ICON_INFO)
    # If script was passed a query, use it to filter posts
    elif query:
        # retrieve cached clients and devices
        clients = wf.cached_data('client', max_age=0)
        devices = wf.cached_data('device', max_age=0)
        radius = wf.cached_data('radius', max_age=0)
        device_map = get_device_map(devices)

        items = [
            {
                'list': clients,
                'commands': client_commands,
                'id': 'mac',
                'filter': search_key_for_client
            },
            {
                'list': devices,
                'commands': device_commands,
                'id': 'mac',
                'filter': search_key_for_device
            },
            {
                'list': radius,
                'commands': radius_commands,
                'id': '_id',
                'filter': search_key_for_radius
            }
        ]

        for item in items:
            parts = extract_commands(args, item['list'], item['filter'])
            query = parts['query']
            item_list = get_filtered_items(query, item['list'], item['filter'])

            # since this i now sure to be a client/device query, fix args if there is a client/device command in there
            command = parts['command'] if 'command' in parts else ''
            params = parts['params'] if 'params' in parts else []

            if item_list:
                if 1 == len(item_list) and (not command or command not in item['commands']):
                    # Single client only, no command or not complete command yet so populate with all the commands
                    single = item_list[0]
                    name = single['_display_name']
                    cmd_list = list(filter(lambda x: x.startswith(command), item['commands'].keys()))
                    cmd_list.sort()
                    log.debug('parts.'+single['_type']+'_command is '+command)
                    for command in cmd_list:
                        if 'upgrade' == command and 'upgradable' in single and not single['upgradable']:
                            continue
                        wf.add_item(title=name,
                                subtitle=command.capitalize()+' '+name,
                                arg=' --'+item['id']+' "'+single[item['id']]+'" --command-type '+single['_type']+' --command '+command+' --command-params '+(' '.join(params)),
                                autocomplete=name+' '+command,
                                valid=bool('arguments' not in item['commands'][command] or params),
                                icon=single['_icon'])
                elif 1 == len(item_list) and (command and command in item['commands'] and command in command_params):
                    single = item_list[0]
                    if 'clients' == command:
                        # show all the details of clients
                        item_list.extend(sorted(get_device_clients(wf, single), key=lambda x: x['_display_name']))
                    else:
                        # single client and has command already - populate with params?
                        name = single['_display_name']
                        param_list = command_params[command]['values'] if 'values' in command_params[command] else []
                        param_start = params[0] if params else ''
                        param_list = list(filter(lambda x: x.startswith(param_start), param_list))
                        param_list.sort()
                        check_regex = False
                        if not param_list and command_params[params]['regex']:
                            param_list.append(parts.client_params[0].lower())
                            check_regex = True
                        for param in param_list:
                            wf.add_item(title=name,
                                    subtitle='Turn '+name+' '+command+' '+param,
                                    arg=' --'+item['id']+' "'+single[item['id']]+'" --command-type '+single['_type']+' --command '+command+' --command-params '+param,
                                    autocomplete=name+' '+command,
                                    valid=bool(not check_regex or re.match(command_params[command]['regex'], param)),
                                    icon=single['_icon'])
                # Loop through the returned clients and add an item for each to
                # the list of results for Alfred
                for single in item_list:
                    name = single['_display_name']
                    item_type = single['_type']
                    wf.add_item(title=name,
                            subtitle=get_item_subtitle(single, item_type, device_map),
                            arg=' --'+item['id']+' "'+single[item['id']]+'" --command-type '+item_type+' --command '+command+' --command-params '+(' '.join(params)),
                            autocomplete=name,
                            valid=False,
                            icon=single['_icon'])

        # Send the results to Alfred as XML
    wf.send_feedback()
    return 0


if __name__ == u"__main__":
    wf = Workflow3(update_settings={
        'github_slug': 'schwark/alfred-unifi'
    })
    log = wf.logger
    sys.exit(wf.run(main))
    