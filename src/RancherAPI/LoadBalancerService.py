#!/usr/bin/env python2.7

from ServiceObject import ServiceObject


class LoadBalancerService(ServiceObject):
	def __init__(self, target_name, **kwargs):
		super(LoadBalancerService, self).__init__(**kwargs)
		self.get_name = lambda: self._get_rw('name')
		self.set_name = lambda name: self._set_rw('name', name)
		self.get_description = lambda: self._get_rw('description')
		self.get_environmentId = lambda: self._get_rw('environmentId')
		self.set_environmentId = lambda envid: self._set_rw('environmentId', envid)
		self.set_description = lambda description: self._set_rw('description', description)
		self.get_certIds = lambda: self._get_rw('certificateIds')
		self.set_certIds = lambda name: self._set_rw('certificateIds', certificateIds)
		self.get_defaultCertId = lambda: self._get_rw('defaultCertificateId')
		self.set_defaultCertId = lambda defaultCert: self._set_rw('defaultCertificateId', defaultCert)

		self.name = property(self.get_name, self.set_name)
		self.description = property(self.get_description, self.set_description)
		self.environmentId = property(self.get_environmentId, self.set_environmentId)
		self.defaultCertificateId = property(self.get_defaultCertId, self.set_defaultCertId)
		self.certificateIds = property(self.get_certIds, self.set_certIds)

		self.__get_target_lb(target_name)

	def _get_payload(self):
		p = {
			"name": self.name,
			"description": self.description,
			"certificateIds": self.certificateIds,
			"defaultCertificateId": self.defaultCertificateId,
			"metadata": self._get_rw('metadata'),
			"loadBalancerConfig": self._get_rw('loadBalancerConfig'),
			"retainIp": self._get_rw('retainIp'),
			"scale": self._get_rw('scale'),
			"scalePolicy": self._get_rw('scalePolicy'),
			"selectorLink": self._get_rw('selectorLink')
		}
		return p

	def __set_ro_data(self, service):
		self._ro_api_data = {
			'id':         service['id'],
			'fqdn':       service['fqdn'],
			'upgrade':    service['upgrade'],
			'externalId': service['externalId'],
			'healthState': service['healthState'],
			'currentScale': service['currentScale'],
			'publicEndpoints': service['publicEndpoints']
		}

	def __set_rw_data(self, service):
		self.name                 = service['name']
		self.description          = service['description']
		self.environmentId        = service['environmentId']
		self.certificateIds       = service['certificateIds']
		self.defaultCertificateId = service['defaultCertificateId']
		self._set_rw('assignServiceIpAddress', service['assignServiceIpAddress'])
		self._set_rw('launchConfig', service['launchConfig'])
		self._set_rw('loadBalancerConfig', service['loadBalancerConfig'])
		self._set_rw('metadata', service['metadata'])
		self._set_rw('retainIp', service['retainIp'])
		self._set_rw('scale', service['scale'])
		self._set_rw('scalePolicy', service['scalePolicy'])
		self._set_rw('selectorLink', service['selectorLink'])
		self._set_rw('startOnCreate', service['startOnCreate'])
		self._set_rw('vip', service['vip'])

	def __get_target_lb(self, target_name):
		for service in self.get_services()['data']:
			if service['name'] == target_name and service['type'] == 'loadBalancerService':
				self.__set_rw_data(service)
				self.__set_ro_data(service)
				self.url                  = '/loadbalancerservices/%s' % self._ro_api_data['id']
				return True

		raise Exception('Target load balancer not found: %s' % target_name)

	def set_service_links(self, serviceLinks):
		self.api_call(self.api_cb_post, self.url + '/?action=setservicelinks', payload = {'serviceLinks': serviceLinks})

	def update(self):
		return self.api_call(self.api_cb_put, self.url, payload = self._get_payload())
