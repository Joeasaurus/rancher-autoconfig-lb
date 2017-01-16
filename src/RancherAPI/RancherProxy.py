import os
import json
import time
import re
import sys
import requests

from APIHandler import MetadataAPI

class RancherProxy(MetadataAPI):
	def __init__(self):
		try:
			self.auth_list = (os.environ["CATTLE_ACCESS_KEY"], os.environ["CATTLE_SECRET_KEY"])
			self.cattle_url = os.environ['CATTLE_URL']
			super(RancherProxy, self).__init__(url = self.cattle_url, auth_list = self.auth_list)
		except KeyError, e:
			self.auth_list = None
			self.cattle_url = None
			super(RancherProxy, self).__init__()

		self.services = []

		self.__get_cattle_info()

	def __get_cattle_info(self):
		self.services = self.get_services()['data']
		print "Got services..."

	def is_suitable_service(self, service):
		return (( service['type'] == 'service') and
			   ( service['state'] not in ('deactivating', 'inactive', 'removed', 'removing')))

	def get_label(self, service, label):
		return service['launchConfig']['labels'][label]
