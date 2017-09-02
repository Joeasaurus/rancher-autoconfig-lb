#!/usr/bin/env python

from ServiceObject import ServiceObject
from datetime import datetime, timedelta

class CertificateService(ServiceObject):
	def __init__(self, **kwargs):
		super(CertificateService, self).__init__(**kwargs)
		self.url = '/certificates/%s'
		self.id = kwargs['id'] if 'id' in kwargs else -1

		self.today = datetime.today()
		self.renewal_days = timedelta(days = kwargs['renewal_days'] if 'renewal_days' in kwargs else 30)

		self.get_name = lambda: self._get_rw('name')
		self.set_name = lambda name: self._set_rw('name', name)
		self.get_cert = lambda: self._get_rw('cert')
		self.set_cert = lambda cert: self._set_rw('cert', cert)
		self.get_key = lambda: self._get_rw('key')
		self.set_key = lambda key: self._set_rw('key', key)
		self.get_certChain = lambda: self._get_rw('certChain')
		self.set_certChain = lambda certChain: self._set_rw('certChain', certChain)
		self.get_description = lambda: self._get_rw('description')
		self.set_description = lambda description: self._set_rw('description', description)

		self.name = property(self.get_name, self.set_name)
		self.cert = property(self.get_cert, self.set_cert)
		self.key = property(self.get_key, self.set_key)
		self.certChain = property(self.get_certChain, self.set_certChain)
		self.description = property(self.get_description, self.set_description)

		if self.id != -1:
			self.retrieve_by_id(self.id)

	def _get_payload(self):
		p = {
			"name": self.name,
			"cert": self.cert,
			"key":  self.key,
		}
		if self.certChain:
			p['certChain'] = self.certChain
		if self.description:
			p['description'] = self.description
		return p

	def retrieve_by_id(self, id):
		api_data = self.api_call(self.api_cb_get, self.url % id)
		#print api_data
		if 'status' in api_data and api_data['status'] == 404:
			raise("404 %s" % api_data)

		self.name = api_data['name']
		self.cert = api_data['cert']
		self.key  = api_data['key']
		self.certChain = api_data['certChain']
		self.description = api_data['description']
		self._ro_api_data = {
			"id": api_data['id'],
			"CN": api_data['CN'],
			"issuedAt":  api_data['issuedAt'],
			"expiresAt": api_data['expiresAt'],
			"keySize":   api_data['keySize'],
			"issuer":    api_data['issuer'],
			"version":   api_data['version'],
			"algorithm": api_data['algorithm'],
			"serialNumber":    api_data['serialNumber'],
			"certFingerprint": api_data['certFingerprint'],
			"subjectAlternativeNames": api_data['subjectAlternativeNames']
		}

	def set_certificate(self, name, cert, key, certChain = None, description = None):
		self.name = name
		self.cert = cert
		self.key  = key
		self.certChain = certChain
		self.description = description

	def due_for_renewal(self):
		expires_stamp = datetime.strptime(self._ro_api_data['expiresAt'], "%a %b %d %X %Z %Y")
		return (self.today - self.renewal_days <= expires_stamp <= self.today + self.renewal_days)

	def create(self):
		print self._get_payload()
		api_data = self.api_call(self.api_cb_post, self.url % '', payload = self._get_payload())
		print api_data

	def update(self):
		print self._get_payload()
		self.api_call(self.api_cb_put, self.url % self.id, payload = self._get_payload())
		print api_data
