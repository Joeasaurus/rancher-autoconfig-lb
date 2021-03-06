#!/usr/bin/env python2.7

import requests
import json
import time
import collections
import re

INTERNAL_META_URL = "http://rancher-metadata.rancher.internal/2015-12-19"

class MetadataAPI(object):
	def __init__(self, **kwargs):
		self.max_attempts = 3
		self.api_url = kwargs['url'] if 'url' in kwargs and kwargs['url'] is not None else INTERNAL_META_URL
		self.meta_url = INTERNAL_META_URL
		self.auth_list = kwargs['auth_list'] if 'auth_list' in kwargs and kwargs['auth_list'] is not None else None

	def api_call(self, callback, url, **kwargs):
		success = False
		i = 1

		if 'meta' in kwargs:
			use_url = self.meta_url + url
		else:
			use_url = self.api_url + url
		#print self.api_url + url

		while (i <= self.max_attempts and not success):
			try:
				if kwargs and 'payload' in kwargs:
					req = callback(use_url, kwargs['payload'])
		  		else:
					req = callback(use_url)

				data = self.no_unicode(req.json())
				success = True
				break
			except Exception as e:
				print("Failed to query Rancher Metadata API on %s - Caught exception (%s)" % (url, str(e)))
				raise e

			i = i + 1

		if not success or self.is_error(data):
			print data
			raise RuntimeError("Failed to query Rancher Metadata API (%d out of %d attempts failed)" % (i, self.max_attempts))

		return data

	def api_cb_get(self, uri):
		return requests.get(uri,
			headers={"Content-Type": "application/json", "Accept": "application/json"},
			auth=self.auth_list
		)

	def api_cb_post(self, uri, payload = {}):
		#print "Posting to ", uri, " with ", payload
		return requests.post(uri,
			data=json.dumps(payload),
			headers={"Content-Type": "application/json", "Accept": "application/json"},
			auth=self.auth_list
		)

	def api_cb_put(self, uri, payload = {}):
		#print "Putting to ", uri, " with ", payload
		return requests.put(uri,
			data=json.dumps(payload),
			headers={"Content-Type": "application/json", "Accept": "application/json"},
			auth=self.auth_list
		)

	def get_certificates(self, **kwargs):
		return self.api_call(self.api_cb_get, "/certificates")

	def get_services(self, **kwargs):
		return self.api_call(self.api_cb_get, "/services", **kwargs)

	def get_service(self, **kwargs):
		if not kwargs:
			return self.api_call(self.api_cb_get, "/self/service", meta = True)
		else:
			if 'service_name' not in kwargs:
				raise ValueError("Must provide the service name")

			if 'stack_name' not in kwargs:
				return self.api_call(self.api_cb_get, "/self/stack/services/%s" % kwargs['service_name'], meta = True)
			else:
				return self.api_call(self.api_cb_get, "/stacks/%s/services/%s" % (kwargs['stack_name'], kwargs['service_name']))

	def get_service_field(self, field, **kwargs):
		if not kwargs:
			return self.api_call(self.api_cb_get, "/self/service/%s" % field)
		else:
			if 'service_name' not in kwargs:
				raise ValueError("Must provide service name")

			if 'stack_name' not in kwargs:
				return self.api_call(self.api_cb_get, "/self/stack/services/%s/%s" % (kwargs['service_name'], field))
			else:
				return self.api_call(self.api_cb_get, "/stacks/%s/services/%s/%s" % (kwargs['stack_name'], kwargs['service_name'], field))

	def get_service_scale_size(self, **kwargs):
		return self.get_service_field("scale", **kwargs)

	def get_service_containers(self, **kwargs):
		containers = {}

		for container in self.get_service_field("containers", **kwargs):
			if 'create_index' in container and isinstance(container['create_index'], basestring):
				container['create_index'] = int(container['create_index'])

			if 'service_index' in container and isinstance(container['service_index'], basestring):
				container['service_index'] = int(container['service_index'])

			containers[container['name']] = container

		return containers

	def get_service_metadata(self, **kwargs):
		return self.get_service_field("metadata", **kwargs)

	def get_service_links(self, **kwargs):
		return self.get_service_field("links", **kwargs)

	def wait_service_containers(self, **kwargs):
		scale = self.get_service_scale_size(**kwargs)

		old = []
		while True:
			containers = self.get_service_containers(**kwargs)
			new = containers.keys()

			for name in list(set(new) - set(old)):
				yield (name, containers[name])

			old = new

			if (len(new) < scale):
				time.sleep(0.5)
			else:
				break

	def get_stacks(self):
		return self.api_call(self.api_cb_get, "/stacks")

	def get_stack(self, stack_name = None):
		if stack_name is None:
			return self.api_call(self.api_cb_get, "/self/stack")
		else:
			return self.api_call(self.api_cb_get, "/stacks/%s" % stack_name)

	def get_stack_services(self, stack_name = None):
		if stack_name is None:
			return self.api_call(self.api_cb_get, "/self/stack/services")
		else:
			return self.api_call(self.api_cb_get, "/stacks/%s/services" % stack_name)

	def get_containers(self):
		containers = []

		for container in self.api_call(self.api_cb_get, "/containers"):
			if 'create_index' in container and isinstance(container['create_index'], basestring):
				container['create_index'] = int(container['create_index'])

			if 'service_index' in container and isinstance(container['service_index'], basestring):
				container['service_index'] = int(container['service_index'])

			containers.append(container)

		return containers

	def get_container(self, container_name = None):
		container = None

		if container_name is None:
			container = self.api_call(self.api_cb_get, "/self/container", meta = True)
		else:
			container = self.api_call(self.api_cb_get, "/containers/%s" % container_name)

		if 'create_index' in container and isinstance(container['create_index'], basestring):
			container['create_index'] = int(container['create_index'])

		if 'service_index' in container and isinstance(container['service_index'], basestring):
			container['service_index'] = int(container['service_index'])

		return container

	def get_container_field(self, field, container_name):
		if container_name is None:
			return self.api_call(self.api_cb_get, "/self/container/%s" % field, meta = True)
		else:
			return self.api_call(self.api_cb_get, "/containers/%s/%s" % (container_name, field))

	def get_container_create_index(self, container_name = None):
		i = self.get_container_field("create_index", container_name)

		if i:
			return int(i)
		else:
			return None

	def get_container_ip(self, container_name = None):
		if container_name is None:
			# are we running within the rancher managed network?
			# FIXME: https://github.com/rancher/rancher/issues/2750
			if self.is_network_managed():
				return self.api_call(self.api_cb_get, "/self/container/primary_ip", meta = True)
			else:
				return self.get_host_ip()
		else:
			return self.api_call(self.api_cb_get, "/containers/%s/primary_ip" % container_name)

	def get_container_name(self, container_name = None):
		return self.get_container_field("name", container_name)

	def get_container_service_name(self, container_name = None):
		return self.get_container_field("service_name", container_name)

	def get_container_stack_name(self, container_name = None):
		return self.get_container_field("stack_name", container_name)

	def get_container_hostname(self, container_name = None):
		return self.get_container_field("hostname", container_name)

	def get_container_service_index(self, container_name = None):
		i = self.get_container_field("service_index", container_name)
		return int(i) if i else None

	def get_container_host_uuid(self, container_name = None):
		return self.get_container_field("host_uuid", container_name)

	def is_network_managed(self):
		# in managed network, we don't get to see any information about the container :(
		return self.get_container_create_index() is not None

	def get_hosts(self):
		return self.api_call(self.api_cb_get, "/hosts")

	def get_host(self, host_name):
		if host_name is None:
			return self.api_call(self.api_cb_get, "/self/host")
		else:
			return self.api_call(self.api_cb_get, "/hosts/%s" % host_name)

	def get_host_field(self, field, host_name):
		if host_name is None:
			return self.api_call(self.api_cb_get, "/self/host/%s" % field)
		else:
			return self.api_call(self.api_cb_get, "/hosts/%s/%s" % (host_name, field))

	def get_host_ip(self, host_name = None):
		return self.get_host_field("agent_ip", host_name)

	def get_host_uuid(self, host_name = None):
		return self.get_host_field("uuid", host_name)

	def get_host_name(self, host_name = None):
		return self.get_host_field("name", host_name)

	def is_error(self, data):
		return (isinstance(data, dict) and ('status' in data and data['status'] != 200))

	def no_unicode(self, h):
		if isinstance(h, basestring):
			return str(h)
		elif isinstance(h, dict):
			return dict(map(self.no_unicode, h.iteritems()))
		elif isinstance(h, collections.Iterable):
			return type(h)(map(self.no_unicode, h))
		else:
			return h
