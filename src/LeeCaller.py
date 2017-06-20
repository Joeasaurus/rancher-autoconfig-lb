#!/usr/bin/env python2.7
import json
import urllib3
import os
from urllib3 import connection_from_url
from multiprocessing import Pool as ProcessPool, TimeoutError

SEED_DATA   = None
HTTP_POOL   = None

def load(seed_path = "lee_seed.json"):
    global SEED_DATA
    global HTTP_POOL

    json_env = os.environ.get('LEE_SEED_JSON', False)

    if os.path.isfile(seed_path):
        with open(seed_path, 'r') as seeds:
            SEED_DATA = json.load(seeds)
    elif json_env:
        SEED_DATA = json.loads(json_env)
    else:
        raise Exception("No Seed Data to load!")

    print SEED_DATA['lee_host']

    HTTP_POOL = connection_from_url("http://%s:%s" % (SEED_DATA['lee_host'], SEED_DATA['lee_port']), maxsize = 5, block=True)

def build_request(tld, common_name, alt_names):
    global SEED_DATA
    try:
        tld_seed = SEED_DATA[tld]
        return {
            'api_key':     SEED_DATA['api_key'],
            'zone_id':     tld_seed['zone_id'],
            'access_key':  tld_seed['access_key'],
            'secret_key':  tld_seed['secret_key'],
            'tld':         tld,
            'common_name': common_name,
            'alt_names':   alt_names
        }
    except KeyError as e:
        return {
            'error': e
        }

def build_response(json_req, json_resp):
    json_resp = json_resp['status']
    try:
        return {
            'tld':         json_req['tld'],
            'common_name': json_req['common_name'],
            'alt_names':   json_req['alt_names'],
            'cert':        json_resp['cert'],
            'chain':       json_resp['im'],
            'key':         json_resp['key']
        }
    except KeyError as e:
        print json_req
        print json_resp
        return {
            'error': e
        }

def make_request(req):
    global HTTP_POOL
    global SEED_DATA
    json_req = build_request(req['tld'], req['common_name'], req['alt_names'])
    if json_req.get('error', False):
        return json_req

    resp = HTTP_POOL.request('POST', "/get_cert", body = json.dumps(json_req).encode('utf-8'), headers = {'Content-Type': 'application/json'}, retries = 0, timeout = 300.0)
    json_resp = json.loads(resp.data.decode('utf-8'))
    return build_response(json_req, json_resp)

def request_certificates(domains):
    THREAD_POOL = ProcessPool(processes=5)
    return THREAD_POOL.map(make_request, domains)

if __name__ == '__main__':
    domains = [
        {
            'tld': 'shadowacre.ltd',
            'common_name': 'jme-test.shadowacre.ltd',
            'alt_names': ['whoknows.jme-test.shadowacre.ltd']
        }
    ]

    load()
    print request_certificates(domains)
