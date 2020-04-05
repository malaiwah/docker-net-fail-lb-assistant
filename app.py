#!/usr/bin/env python
import threading
import atexit
import iptc
import os
import re
import json
import uuid
from timeit import default_timer as timer
import dns.resolver
import netifaces

from flask import Flask, jsonify

app = Flask(__name__)

UUID_SHORT_LEN = 8 # Truncate uuids
CONFIG_FILE = 'netconfig.json'
DEFAULT_TIMER_SECS = 10 #Seconds
DEFAULT_DNS_LIFETIME = 2 #seconds
DEFAULT_INTERFACES_FILTER = "" # matches everything
DEFAULT_QUERIES = [
    "www.oracle.com",
    "www.microsoft.com"
]
DEFAULT_DNS_SERVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1"
]
DEFAULT_NETFILTER_CHAIN = "NET_BALANCE"

netfilter_table = False

# variables that are accessible from anywhere
commonDataStruct = { 
    'uuid':  str(uuid.uuid4())[:UUID_SHORT_LEN],
    'ticks': 0
}

# lock to control access to variable
dataLock = threading.Lock()
# thread handler
yourThread = threading.Thread()

old_jump_chains = []

def interrupt():
    try:
        yourThread.cancel()
    # Ignore if thread can't be cancelled
    except AttributeError:
        pass

# When you kill Flask (SIGTERM), clear the trigger for the next thread
atexit.register(interrupt)

# Holding the lock is left to the the caller
def _monitor():
    # Only run if configuration is loaded
    if 'loaded_at' in commonDataStruct.keys():
        results = []
        for source in commonDataStruct['source_ips']:
            for destination in commonDataStruct['dns_servers']:
                for query_qname in commonDataStruct['queries']:
                    query_type = 'A'
                    app.logger.debug("From {} to {} for {}".format(source, destination, query_qname))
                    try:
                        resolver = commonDataStruct['resolvers'][destination]
                        time_before = timer()
                        answers = resolver.query(query_qname, query_type,
                            source=source,
                            lifetime=commonDataStruct['timeout']
                        )
                        time_after = timer()
                        time_diff = time_after - time_before
                        # If any result returned, consider the test passing
                        result = True
                        app.logger.debug("Answers for {} returned in {}s for {}->{}: {}".format(query_qname, time_diff, source, destination, len(answers)))

                    # Broad catch all, just in case
                    except Exception as e:
                        app.logger.warning("Error on {}->{} for {} ({})".format(source, destination, query_qname, e))
                        result = False
                    
                    results.append({ 'query': query_qname,
                        'source': source,
                        'destination': destination,
                        'result': result
                    })
        
        # Discard queries that had just failures
        app.logger.debug("Original traffic interfaces: {}".format(", ".join(set([ i['source'] for i in results if 'invalid' not in i.keys() ]))))

        results = _remove_failed_results(results, 'query')
        app.logger.debug("Filtered after queries filter: {}".format(", ".join(set([ i['query'] for i in results if 'invalid' not in i.keys() ]))))

        # Discard destinations that had just failures
        results = _remove_failed_results(results, 'destination')
        app.logger.debug("Filtered after destination filter: {}".format(", ".join(set([ i['destination'] for i in results if 'invalid' not in i.keys() ]))))

        # Discard interfaces that had just failures
        results = _remove_failed_results(results, 'source')

        # If nothing left, enable everything
        valid_ifaces = set([ i['source'] for i in results if 'invalid' not in i.keys() ])
        if len(valid_ifaces) == 0:
            app.logger.warning("Warning. No valid traffic interface found. Enabling them all (flood mode).")
            valid_ifaces = commonDataStruct['source_ips']

        # Enable interfaces/chains that are left
        app.logger.info("Valid traffic interfaces: {}".format(", ".join(valid_ifaces)))

        return sorted([ 'chain-{}'.format(i) for i in valid_ifaces ])

def doStuff():
    global old_jump_chains
    app.logger.info("{}: Timer {} tick at {}".format(commonDataStruct['uuid'], commonDataStruct['ticks'], timer()))
    
    # Lock when doing it in a thread
    with dataLock:
        # Do your stuff with commonDataStruct Here
        commonDataStruct['ticks'] = commonDataStruct['ticks'] + 1
        
        jump_chains = _monitor()

    if ("|".join(old_jump_chains) != "|".join(jump_chains)):
        app.logger.info("Updating jump chains")       
        old_jump_chains =  _manage_rules(jump_chains)

    # Set the next thread to happen
    intval = 30 # default at 30 seconds if configuration is not loaded
    if 'interval' in commonDataStruct.keys():
        intval = commonDataStruct['interval']
    yourThread = threading.Timer(intval, doStuff, ())
    yourThread.start() 

def _remove_failed_results(results, k, result_key = 'result', invalid_key = 'invalid'): 
    all_values = [ i[k] for i in results if invalid_key not in i.keys() ]
    unique_values = set(all_values)
    for v in unique_values:
        filtered_results = [ i for i in results if i[k] == v ]
        bad_results = [i for i in filtered_results if i[result_key] != True ]
        app.logger.debug("{}/{} bad results for {}".format(len(bad_results), len(filtered_results), v))
        if (len(bad_results) == len(filtered_results)):
            for vv in results:
                if vv[k] == v:
                    vv[invalid_key] = True
    #app.logger.debug("{}".format(json.dumps(results)))
    return results

@app.route('/healthcheck')
def healthcheck():
    return jsonify({'healthy': True})

# Will be initialized once Docker (or anything) hits the healthcheck the first time
@app.before_first_request
def init_scheduler():
    doStuff()

@app.route('/.admin/reload')
def load_config():
    ret = _load_config()
    return jsonify({'reloaded': ret})

def _config_value(config, key, default_value=None):
    ret = default_value
    if key in config.keys():
        ret = config[key]
    return ret

def _load_config():
    app.logger.info("Loading configuration file [{}]".format(CONFIG_FILE))
    interfaces = netifaces.interfaces()
    try:
        config = json.load(open(CONFIG_FILE))
    except ValueError as e:
        app.logger.error("Error loading configuration file: {}".format(e))
        return False

    interfaces_filter = _config_value(config, 'interfaces_filter', DEFAULT_INTERFACES_FILTER)
    source_ips = []
    for iface in interfaces:
        if re.match(interfaces_filter, iface):
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs.keys():
                for addr in addrs[netifaces.AF_INET]:
                    app.logger.info("Using source IP [{}] from interface [{}]".format(addr['addr'], iface))
                    source_ips.append(addr['addr'])

    with dataLock:
        commonDataStruct['raw_config'] = config
        commonDataStruct['interval'] = int(_config_value(config, 'interval', DEFAULT_TIMER_SECS))
        commonDataStruct['timeout'] = int(_config_value(config, 'timeout', DEFAULT_TIMER_SECS))
        commonDataStruct['interfaces_filter'] = interfaces_filter
        commonDataStruct['queries'] = _config_value(config, 'queries', DEFAULT_QUERIES)
        commonDataStruct['dns_servers'] = _config_value(config, 'dns_servers', DEFAULT_DNS_SERVERS)
        commonDataStruct['netfilter_chain_name'] = _config_value(config, 'netfilter_chain_name', DEFAULT_NETFILTER_CHAIN)
        commonDataStruct['resolvers'] = {}
        for destination in commonDataStruct['dns_servers']:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ destination ]
            commonDataStruct['resolvers'][destination] = resolver
        commonDataStruct['source_ips'] = source_ips

        commonDataStruct['loaded_at'] = timer()

    _manage_chain()

    return True

def _manage_chain():
    global netfilter_table
    try:
        if netfilter_table == False:
            netfilter_table = iptc.Table(iptc.Table.MANGLE)
        if commonDataStruct['netfilter_chain_name'] not in netfilter_table.chains:
            iptc.easy.add_chain('mangle', commonDataStruct['netfilter_chain_name'])
    except iptc.ip4tc.IPTCError as e:
        app.logger.warning("Exception creating managed objects: {}".format(e))

def _manage_rules(jump_to = []):
    global netfilter_table

    jumped_to = []

    original_autocommit = netfilter_table.autocommit
    netfilter_table.autocommit = False
    netfilter_table.refresh()
    chain = iptc.Chain(netfilter_table, commonDataStruct['netfilter_chain_name'])
    
    # Clear all rules
    for rule in chain.rules:
        chain.delete_rule(rule)

    possible_jumps = [ jump for jump in jump_to if netfilter_table.is_chain(jump) ]
    idx = 0
    for jump in possible_jumps:
        try:
            #rule_d = {'protocol': 'tcp', 'target': {'goto': jump}, 'tcp': {'dport': '22'}}
            #iptc.easy.insert_rule('filter', commonDataStruct['netfilter_chain_name'], rule_d)
            rule = iptc.Rule()
            rule.target = rule.create_target(jump, goto=True)
            #rule.protocol = "tcp"

            #iptables -t mangle -A PREROUTING -p tcp -m state --state NEW -m statistic --mode nth --every 2 --packet 0 -j CONNMARK1
            match_c = rule.create_match("comment")
            match_c.comment = "{}.created_at_tick_{}".format(commonDataStruct['uuid'], commonDataStruct['ticks'])
            
            match_s = rule.create_match("state")
            match_s.state = "NEW"

            # Only invoke the statistics module if more than one chain to be distributed to
            if len(possible_jumps) > 1:
                match_t = rule.create_match("statistic")
                match_t.mode = "nth"
                match_t.every = str(len(possible_jumps))
                match_t.packet = str(idx)

            chain.append_rule(rule)
            idx = idx + 1
            app.logger.debug("Chain found, rule added: {}".format(match_c.comment))
            
            jumped_to.append(jump)
            
        except Exception as e:
            app.logger.debug("Exception raised while managing rules, ignoring: {}".format(e))

    netfilter_table.commit()
    netfilter_table.autocommit = original_autocommit

    return jumped_to

@app.route('/.admin/dump')
def dump_netfilter_table(iptc_table = iptc.Table.MANGLE):
    ret = []
    table = iptc.Table(iptc_table)
    for chain in table.chains:
        ret.append("=======================")
        ret.append("Chain {}".format(chain.name))
        for rule in chain.rules:
            ret.append("Rule\tproto: {}\tsrc: {}\tdst: {}\tin: {}\tout: {}".format(rule.protocol, rule.src, rule.dst, rule.in_interface, rule.out_interface))
            for match in rule.matches:
                ret.append("Matches: {}".format(match))
            ret.append("Target: {}".format(rule.target.name))
    ret.append("=======================\n")
    return "<pre>{}</pre>".format("\n".join(ret))

# Startup
_load_config()
_monitor()