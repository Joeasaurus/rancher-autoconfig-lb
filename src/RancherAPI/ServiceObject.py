#!/usr/bin/env python2.7

import logging
from APIHandler import MetadataAPI

class ServiceObject(MetadataAPI):
	def __init__(self, **kwargs):
		super(ServiceObject, self).__init__(**kwargs)
		self._rw_api_data = {}
		self._ro_api_data = {}

	def _get_rw(self, key):
		return self._rw_api_data[key]
	def _set_rw(self, key, val):
		self._rw_api_data[key] = val

	def or_default(self, inmap, inkey, default = None):
		try:
			return inmap[inkey]
		except KeyError:
			return default

	def create(self):
		logging.error("You called the base class boi" + self.name)

	def update(self):
		logging.error("You called the base class boi" + self.name)

	def delete(self):
		logging.error("You called the base class boi" + self.name)
