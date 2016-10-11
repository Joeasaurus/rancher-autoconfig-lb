#!/usr/bin/env python2.7

from ServiceObject import ServiceObject


class LoadBalancerService(ServiceObject):
	def __init__(self, target_name, **kwargs):
		super(LoadBalancerService, self).__init__(**kwargs)
		self.name = target_name
		self.id = -1
		self.env_id = ""
		self.description = ""

		self.certificateIds = []
		self.defaultCertificateId = None # Takes RancherCertificate object?

		self.service_data = {}
		self.__get_target_lb()

	def __get_target_lb(self):
		for service in self.get_services()['data']:
			if service['name'] == self.name and service['type'] == 'loadBalancerService':
				self.id                   = service['id']
				self.env_id               = service['environmentId']
				self.certificateIds       = service['certificateIds']
				self.defaultCertificateId = service['defaultCertificateId']
				self.url                  = '/loadbalancerservices/%s' % self.id
				self.service_data         = service
				return self.id

		raise Exception('Target load balancer not found: %s' % self.TARGET_SERVICE)

	def set_service_links(self, serviceLinks):
		self.api_call(self.api_cb_post, self.url + '/?action=setservicelinks', payload = {'serviceLinks': serviceLinks})

	def update(self):
		u_payload = {
			"name": self.name,
			"description": self.description,
			"certificateIds": self.certificateIds,
			"defaultCertificateId": self.defaultCertificateId,
			"metadata": self.service_data['metadata'],
			"loadBalancerConfig": self.service_data['loadBalancerConfig'],
			"retainIp": self.service_data['retainIp'],
			"scale": self.service_data['scale'],
			"scalePolicy": self.service_data['scalePolicy'],
			"selectorLink": self.service_data['selectorLink']
		}
		self.api_call(self.api_cb_put, self.url, payload = u_payload)
