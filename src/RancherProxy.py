import os
import json
import time
import re
import sys
import requests

from RancherAPI import MetadataAPI
from RancherAPI import LoadBalancerService

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

class RancherProxy(MetadataAPI):
	def __init__(self):
		try:
			self.auth_list = (os.environ["CATTLE_ACCESS_KEY"], os.environ["CATTLE_SECRET_KEY"])
		except KeyError, e:
			self.auth_list = None

		super(RancherProxy, self).__init__(os.environ["CATTLE_URL"], auth_list = self.auth_list)

		self.target_loadbalancer_name = None

		self.services = []
		self.route_list = ChangingList()

		self.__get_cattle_info()
		# self.lb_service = RancherLoadBalancerService(self.TARGET_SERVICE, self.envid, self.CATTLE_URL)

	def __get_cattle_info(self):
		self.services = self.get_services()['data']

		try:
			self.target_loadbalancer_name = os.environ["TARGET_SERVICE"]
		except KeyError, e:
			try:
				self_container = self.get_container()
				self.target_loadbalancer_name = self_container['labels']['autoconfig.proxy.service_name']
			except KeyError, e:
				raise Exception("You must set label autoconfig.proxy.service_name as target load balancer name")


		self.lb_service = LoadBalancerService(self.target_loadbalancer_name, os.environ["CATTLE_URL"], auth_list = self.auth_list)

		print "Got services..."

	def is_tagged_service(self, service):
		return (( service['type'] == 'service') and
			   ( service['state'] not in ('deactivating', 'inactive', 'removed', 'removing')) and
			   ( 'autoconfig.proxy.routes' in service['launchConfig']['labels'] ))

	def get_label(self, service, label):
		return service['launchConfig']['labels'][label]

	def __check_routes(self, routes):
		for r in routes:
			if not re.match(r'^[a-zA-Z0-9=:/\.\-\_]+$', r):
				raise Exception('Domains format are invalid: %s' % r)

	def __get_route_list(self):
		#print "Parsing route labels..."
		self.route_list.new_list()

		for service in self.services:
			# print "Label for ", service['name']
			try:
				if self.is_tagged_service(service):
					routes = self.get_label(service, 'autoconfig.proxy.routes').replace(' ', '').split(';')
					self.__check_routes(routes)

					self.route_list.append({'serviceId': service['id'], 'ports': routes})

			except Exception, e:
				print >> sys.stderr, 'Error when parsing routes: ' + str(e) + ', ' + str(service)

		return self.route_list.has_changes('serviceId', 'ports')


	def __set_routes_on_lb(self, r_list):
		self.lb_service.set_service_links(r_list)

	def update(self):
		r_changed, r_add, r_remove, r_update = self.__get_route_list()
		if r_changed:
			self.__set_routes_on_lb(self.route_list.list)
			print "Set routes on LB!"
