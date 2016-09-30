#!/usr/bin/env python


import os
import json
import time
import re
import sys
import requests

META_URL = 'http://rancher-metadata.rancher.internal/2015-12-19'

try:
    CATTLE_URL = os.environ["CATTLE_URL"]
    CATTLE_ACCESS_KEY = os.environ["CATTLE_ACCESS_KEY"]
    CATTLE_SECRET_KEY = os.environ["CATTLE_SECRET_KEY"]

    try:
        TARGET_SERVICE = os.environ["TARGET_SERVICE"]
    except:
        try:
            r = requests.get('%s/self/container/labels/autoconfig.proxy.service_name' % META_URL)
            r.raise_for_status()
            TARGET_SERVICE = r.text
        except:
            print >> sys.stderr, "You must set label autoconfig.proxy.service_name as target load balancer name"
            time.sleep(15)
            sys.exit(1)
except:
    print >> sys.stderr, "You must set label 'io.rancher.container.create_agent: true' and 'io.rancher.container.agent.role: environment' for this service"
    time.sleep(15)
    sys.exit(1)

class ChangingList(object):
    def __init__(self):
        self.list = []
        self.last_list = []
        self.changed = False

    def append(self, newitem):
        self.list.append(newitem)

    def new_list(self):
        self.last_list = self.list
        self.list = []

    def has_changes(self, key_a, key_b):
        add = []
        remove = []
        update = []

        _old = dict([(x[key_a], x[key_b]) for x in self.last_list])
        _new = dict([(x[key_a], x[key_b]) for x in self.list])

        for k in (set(_new) - set(_old)):
            add.append({k: _new[k]})

        for k in (set(_old) - set(_new)):
            remove.append({k: _old[k]})

        for k in (set(_new) & set(_old)):
            if set(_new[k]) != set(_old[k]):
                update.append([{k: _old[k]}, {k: _new[k]}])

        self.changed = ( (len(add) > 0) or (len(remove) > 0) or (len(update) > 0) )

        return (self.changed, add, remove, update)

class RancherProxy(object):
    def __init__(self):
        self.envid = ""
        self.services = []
        self.route_list = ChangingList()
        self.cert_list = ChangingList()

        self.__get_cattle_info()

    def __cattle_get(self, uri):
        r = requests.get(uri,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            auth=(CATTLE_ACCESS_KEY, CATTLE_SECRET_KEY),
        )

        if r.status_code != 200:
            raise Exception("Failed to request data: %s" % r.text)

        return r

    def __cattle_post(self, uri, payload = {}):
        print "Posting to ", uri, " with ", payload
        r = requests.post(uri,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            auth=(CATTLE_ACCESS_KEY, CATTLE_SECRET_KEY),
        )

        if r.status_code != 200:
            raise Exception("Failed to post data: %s" % r.text)

    def __get_cattle_info(self):
        uuid = requests.get('%s/self/stack/environment_uuid' % META_URL).text
        self.envid = self.__cattle_get('%s/projects?uuid=%s' % (CATTLE_URL, uuid)).json()['data'][0]['id']

        self.services = self.__cattle_get('%s/projects/%s/services' % (CATTLE_URL, self.envid)).json()['data']
        self.certificates = self.__cattle_get('%s/certificates' % CATTLE_URL)
        print "Got services and certificates..."

    def __is_basic_service(self, service):
        return (( service['type'] == 'service') and
               ( service['state'] not in ('deactivating', 'inactive', 'removed', 'removing')) and
               ( 'autoconfig.proxy.routes' in service['launchConfig']['labels'] ))

    def __is_certed_service(self, service):
        return (self.__is_basic_service(service) and ( 'autoconfig.proxy.certificates' in service['launchConfig']['labels'] ))

    def __get_label(self, service, label):
        return service['launchConfig']['labels'][label]

    def __check_routes(self, routes):
        for r in routes:
            if not re.match(r'^[a-zA-Z0-9=:/\.\-\_]+$', r):
                raise Exception('Domains format are invalid: %s' % r)

    def __get_route_list(self):
        print "Parsing route labels..."
        self.route_list.new_list()

        for service in self.services:
            print "Label for ", service['name']
            try:
                if self.__is_basic_service(service):
                    routes = self.__get_label(service, 'autoconfig.proxy.routes').replace(' ', '').split(';')
                    self.__check_routes(routes)

                    self.route_list.append({'serviceId': service['id'], 'ports': routes})

            except Exception, e:
                print >> sys.stderr, 'Error when parsing routes: ' + str(e) + ', ' + str(service)

        return self.route_list.has_changes('serviceId', 'ports')

    def __get_cert_list(self):
        self.cert_list.new_list()

        for service in self.services:
            try:
                if self.__is_certed_service(service):
                    certstring = self.__get_label(service, 'autoconfig.proxy.certificates')

                    # i.e. TITLE : COMMA LIST ; TITLE.....
                    separate_certs = certstring.replace(' ', '').split(';')

                    for certspec in separate_certs[:]:

                        title_split = certspec.split(':')
                        alt_names = ""

                        if len(title_split) > 1:
                            alt_names = title_split[1]

                        self.cert_list.append({'title': title_split[0], 'alt_names': [alt_names]})

            except Exception, e:
                print >> sys.stderr, 'Error when parsing certs: ' + str(e) + ', ' + str(service)

        return self.cert_list.has_changes('title', 'alt_names')

    def __get_target_lb(self):
        for service in self.services:
            if service['name'] == TARGET_SERVICE and service['type'] == 'loadBalancerService':
                return service['id']
        raise Exception('Target load balancer not found: %s' % TARGET_SERVICE)

    def __set_routes_on_lb(self, lb_id, r_list):
          self.__cattle_post(
            '%s/projects/%s/loadbalancerservices/%s/?action=setservicelinks' % (CATTLE_URL, self.envid, lb_id),
            {'serviceLinks': r_list})

    def __add_update_certs(add_these, update_these):
        print

    def update(self):
        target_lb = self.__get_target_lb()
        print "Got target lb ", target_lb

        r_changed, r_add, r_remove, r_update = self.__get_route_list()
        if r_changed:
            self.__set_routes_on_lb(target_lb, self.route_list.list)
            print "Set routes on LB!"

        c_changed, c_add, c_remove, c_update = self.__get_cert_list()
        if c_changed:
            print "Set certificates in Rancher & LB!"
            # self.le.getcerts(c_add, c_update)
            # self.__add_update_certs(c_add, c_update)
            # self.__set_certs_on_lb(c_add, c_update)


if __name__ == '__main__':
    rp = RancherProxy()

    while True:
        try:
            rp.update()
        except Exception, e:
            print >> sys.stderr, 'System error: ' + str(e)

        time.sleep(10)


#
#
#
#   ^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$
#   alt_names = []
#
#                         if len(title_split) > 1:
#                             alt_names = [title_split[1].split(',')]
#                             alt_names = alt_names[:-1] if alt_names[-1] == '' else alt_names
#
#             {
#     "cert": "string",
#     "certChain": "string",
#     "description": "string",
#     "key": "string",
#     "name": "string"
# }
