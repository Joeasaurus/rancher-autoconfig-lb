#!/usr/bin/env python2.7

import logging
from APIHandler import MetadataAPI

class ServiceObject(MetadataAPI):
	def create(self):
		logging.error("You called the base class boi" + self.name)

	def update(self):
		logging.error("You called the base class boi" + self.name)

	def delete(self):
		logging.error("You called the base class boi" + self.name)

	def is_error(self, data):
		if isinstance(data, dict):
			if 'code' in data and data['code'] == 404:
				return True

		return False
