#!/usr/bin/env python2.7

from ServiceObject import ServiceObject

class LBConfig(ServiceObject):
	def __init__(self, **kwargs):
		super(LBConfig, self).__init__(**kwargs)
		self.get_certIds = lambda: self._get_rw('certificateIds')
		self.set_certIds = lambda name: self._set_rw('certificateIds', certificateIds)
		self.get_defaultCertId = lambda: self._get_rw('defaultCertificateId')
		self.set_defaultCertId = lambda defaultCert: self._set_rw('defaultCertificateId', defaultCert)
		self.get_portRules = lambda: self._get_rw('portRules')
		self.set_portRules = lambda portRules: self._set_rw('portRules', portRules)

		self.defaultCertificateId = property(self.get_defaultCertId, self.set_defaultCertId)
		self.certificateIds = property(self.get_certIds, self.set_certIds)
		self.portRules = property(self.get_portRules, self.set_portRules)

	def payload(self):
		p = {
			"config": self._get_rw('config'),
			"defaultCertificateId": self.defaultCertificateId,
			"certificateIds": self.certificateIds,
			"portRules": self.portRules
			#"stickinessPolicy": self._get_rw('stickinessPolicy')
		}
		return p

	def populate(self, lbconfig):
		self.certificateIds       = self.or_default(lbconfig, 'certificateIds', [])
		self.defaultCertificateId = lbconfig['defaultCertificateId']
		self.portRules            = lbconfig['portRules']
		self._set_rw('config', self.or_default(lbconfig, 'config', {}))
		#self._set_rw('stickinessPolicy', lbconfig['stickinessPolicy'])
		return self


class LoadBalancerService(ServiceObject):
	def __init__(self, target_name, **kwargs):
		super(LoadBalancerService, self).__init__(**kwargs)
		self.get_name = lambda: self._get_rw('name')
		self.set_name = lambda name: self._set_rw('name', name)
		self.get_description = lambda: self._get_rw('description')
		self.set_description = lambda description: self._set_rw('description', description)
		self.get_lbconfig = lambda: self._get_rw('lbConfig')
		self.set_lbconfig = lambda lbc: self._set_rw('lbConfig', lbc)

		self.name = property(self.get_name, self.set_name)
		self.lbConfig = property(self.get_lbconfig, self.set_lbconfig)
		self.description = property(self.get_description, self.set_description)

		self.__get_target_lb(target_name)

	def _get_payload(self):
		p = {
			"name": self.name,
			"description": self.description,
			"launchConfig": self._get_rw('launchConfig'),
			"metadata": self._get_rw('metadata'),
			"lbConfig": self.lbConfig.payload(),
			"retainIp": self._get_rw('retainIp'),
			"scale": self._get_rw('scale'),
			"scalePolicy": self._get_rw('scalePolicy'),
			"selectorLink": self._get_rw('selectorLink')
		}
		return p

	def __set_ro_data(self, service):
		self._ro_api_data = {
			'id':              service['id'],
			'fqdn':            service['fqdn'],
			'upgrade':         service['upgrade'],
			'healthState':     service['healthState'],
			'currentScale':    service['currentScale'],
			'publicEndpoints': service['publicEndpoints']

		}

	def __set_rw_data(self, service):
		self.name        = service['name']
		self.description = service['description']
		self.lbConfig    = LBConfig().populate(service['lbConfig'])
		self._set_rw('externalId', service['externalId'])
		self._set_rw('assignServiceIpAddress', service['assignServiceIpAddress'])
		self._set_rw('launchConfig', service['launchConfig'])
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
				self.url                  = '/loadBalancerServices/%s' % self._ro_api_data['id']
				return True

		raise Exception('Target load balancer not found: %s' % target_name)

	def set_service_links(self, serviceLinks):
		self.api_call(self.api_cb_post, self.url + '/?action=setservicelinks', payload = {'serviceLinks': serviceLinks})

	def update(self):
		#print self.lbConfig.payload()
		return self.api_call(self.api_cb_put, self.url, payload = self._get_payload())
