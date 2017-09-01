from RancherAPI import *
import LeeCaller
import subprocess, sys, os
from datetime import datetime, timedelta

class CertUpdater(RancherProxy):
	def __init__(self, working_dir):
		self.target_loadbalancer_name = None
		super(CertUpdater, self).__init__()

		try:
			self.target_loadbalancer_name = os.environ["TARGET_SERVICE"]
		except KeyError, e:
			try:
				self_container = self.get_container()
				self.target_loadbalancer_name = self_container['labels']['autoconfig.proxy.service_name']
			except KeyError, e:
				raise Exception("You must set label autoconfig.proxy.service_name as target load balancer name")

		LeeCaller.load(os.path.join(working_dir, 'lee_seed.json'))

		self.lb_service = LoadBalancerService(self.target_loadbalancer_name, url = self.cattle_url, auth_list = self.auth_list)

		self.cert_labels = []

		self.__get_certificates()

	def __is_certed_service(self, service):
		return (self.is_suitable_service(service) and ( 'autoconfig.proxy.certificates' in service['launchConfig']['labels'] ))

	def __get_certificates(self):
		self.certs_in_rancher = {}
		self.certificates = self.get_certificates()['data']

		for s_cert in self.certificates:
			cs = CertificateService(url = self.api_url, id = s_cert['id'], auth_list = self.auth_list)

			self.certs_in_rancher[s_cert['CN']] = {
				'id':        s_cert['id'],
				'expiresAt': s_cert['expiresAt'],
				'cert_service': cs
			}

		return self.certs_in_rancher

	def __get_renewal_certificates(self):
		self.certs_for_renewal = {}

		for cert, deets in self.certs_in_rancher.iteritems():
			#print cert, deets
			if deets['cert_service'].due_for_renewal():
				self.certs_for_renewal[cert] = deets

		return self.certs_for_renewal

	def __get_cert_labels(self):
		# Move current list to old, so we can populate and compare
		self.cert_labels = []

		# For each services, lets check their certificates label and keep a list :)
		for service in self.services:
			if self.__is_certed_service(service):
				certstring = self.get_label(service, 'autoconfig.proxy.certificates')

				# i.e. TLD : TITLE : COMMA LIST ; TITLE.....
				separate_certs = certstring.replace(' ', '').split(';')

				for certspec in separate_certs:
					title_split = certspec.split(':')
					alt_names = []

					if len(title_split) > 2:
						alt_names = title_split[2:]

					self.cert_labels.append({'tld': title_split[0], 'common_name': title_split[1], 'alt_names': alt_names})

		return self.cert_labels

	def __get_file_contents(self, filename):
		data = None
		with open(filename, 'r') as opened:
			data = opened.read()

		return data

	def __update_certs_in_rancher(self, certs):
		for cert_deets in certs:
			print "CERT UPDATING IN RANCHER: ", str(cert_deets)
			name = cert_deets['common_name']
			description = "Managed by rancher-autoconfig-lb"

			if name in self.certs_in_rancher:
				cert_service = self.certs_in_rancher[name]['cert_service']
			else:
				cert_service = CertificateService(url = self.api_url, auth_list = self.auth_list)

			if cert_deets['cert']:
				cert_service.cert = cert_deets['cert']
				cert_service.key = cert_deets['key']
				cert_service.certChain = cert_deets['chain']

			cert_service.name = name
			cert_service.description = description

			if cert_deets.has_key('id'):
				print "Updating existing cert by ID"
				cert_service.update()
			else:
				print "Setting cert brand new"
				cert_service.create()

	def __update_certs_on_lb(self, newcerts):
		self.__get_certificates()
		lbconfig = self.lb_service.lbConfig
		dcid = lbconfig.defaultCertificateId
		cids = lbconfig.certificateIds
		print "DUMPING CIDS: ", str(cids)
		if not cids:
			cids = []

		for cert_deets in newcerts:
			name = cert_deets['common_name']
			print name, self.certs_in_rancher
			if name in self.certs_in_rancher:
				cert_id = self.certs_in_rancher[name]['cert_service'].id

				if dcid is None:
					lbconfig.defaultCertificateId = dcid = cert_id
				elif cert_id not in [dcid] + cids:
					cids.append(cert_id)
				else:
					print "Certificate already registered on LB"

		if len(cids) > 0:
			lbconfig.certificateIds = cids

		print "DUMPING LBCONFIG PAYLOAD:"
		print lbconfig.payload()

		self.lb_service.lbConfig = lbconfig

		return self.lb_service.update()

	def __loop_cert_labels(self, labels, callback):
		for label in labels:
			label_cn = label.keys()[0]
			label_cn_dict = {
				'common_name': label_cn,
				'alt_names': label[label_cn]
			}
			callback(label_cn_dict)

	def update(self):
		print "Retrieving certificates from rancher: "
		self.__get_certificates()
		self.__get_renewal_certificates()
		print self.certs_in_rancher

		certs_to_retrieve = []
		certs_not_renewal = []

		print "Getting certificate labels from services:"
		self.__get_cert_labels()
		print self.cert_labels

		def check_for_retrieval(cn_dict):
			if cn_dict['common_name'] in self.certs_in_rancher:
				cn_dict['id'] = self.certs_in_rancher[cn_dict['common_name']]['id']
				if not self.certs_for_renewal.has_key(cn_dict['common_name']):
					return certs_not_renewal.append(cn_dict)

			certs_to_retrieve.append(cn_dict)


		for label in self.cert_labels:
			check_for_retrieval(label)
		# self.__loop_cert_labels(self.cert_labels, check_for_retrieval)

		# print self.certs_for_renewal
		# print certs_not_renewal

		print "Certificates we will retrieve: "
		print certs_to_retrieve

		retrieved_certs = LeeCaller.request_certificates(certs_to_retrieve)
		success_certs   = [x for x in retrieved_certs if not x.has_key('error')]
		fail_certs      = [x for x in retrieved_certs if x.has_key('error')]
		print "SUCCESSES: ", str(success_certs)
		print "ERRORS ", str(fail_certs)
		self.__update_certs_in_rancher(success_certs)
		self.__update_certs_on_lb(certs_not_renewal + success_certs)

		print "Set certificates in Rancher & LB!"
