from RancherProxy import RancherProxy, ChangingList
from RancherAPI import CertificateService
import subprocess, sys, os
from datetime import datetime, timedelta
from LEProxy import LEProxy

class RancherCertProxy(RancherProxy):
	def __init__(self, working_dir):
		self.le = LEProxy(working_dir)
		super(RancherCertProxy, self).__init__()

		self.cert_labels = ChangingList()

		self.__get_certificates()


	def __is_certed_service(self, service):
		return (self.is_tagged_service(service) and ( 'autoconfig.proxy.certificates' in service['launchConfig']['labels'] ))

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
		self.cert_labels.new_list()
		#self.cert_labels.last_list.append({'CN': u'git.shadowacre.ltd', 'alt_names': [u'docker-registry.git.shadowacre.ltd']})

		# For each services, lets check their certificates label and keep a list :)
		for service in self.services:
			if self.__is_certed_service(service):
				certstring = self.get_label(service, 'autoconfig.proxy.certificates')

				# i.e. TITLE : COMMA LIST ; TITLE.....
				separate_certs = certstring.replace(' ', '').split(';')

				for certspec in separate_certs:
					title_split = certspec.split(':')
					alt_names = []

					if len(title_split) > 1:
						alt_names = title_split[1:]

					self.cert_labels.append({'CN': title_split[0], 'alt_names': alt_names})

		return self.cert_labels.has_changes('CN', 'alt_names')

	def __get_file_contents(self, filename):
		data = None
		with open(filename, 'r') as opened:
			data = opened.read()

		return data

	def __update_certs_in_rancher(self, certs):
		for cert_deets in certs:
			print cert_deets
			name = cert_deets['CN']
			description = "Managed by rancher-autoconfig-lb"

			if name in self.certs_in_rancher:
				cert_service = self.certs_in_rancher[name]['cert_service']
			else:
				cert_service = CertificateService(url = self.api_url, auth_list = self.auth_list)

			if cert_deets['ssl']:
				cert_service.cert = self.__get_file_contents(cert_deets['ssl']['cert'])
				cert_service.key = self.__get_file_contents(cert_deets['ssl']['key'])
				cert_service.certChain = self.__get_file_contents(cert_deets['ssl']['im'])

			cert_service.name = name
			cert_service.description = description

			if cert_deets.has_key('id'):
				print "Updating existing cert by ID"
				cert_service.update()
			else:
				print "Setting cert brand new"
				cert_service.create()

	def __update_certs_on_lb(self, certs_to_add, certs_to_remove):
		self.__get_certificates()
		dcid = self.lb_service.defaultCertificateId
		cids = self.lb_service.certificateIds
		if not cids:
			cids = []

		for cert_to_add in certs_to_add:
			cn = cert_to_add.keys()[0]
			if cn in self.certs_in_rancher:
				cert_id = self.certs_in_rancher[cn]['cert_service'].id

				if dcid is None:
					self.lb_service.defaultCertificateId = dcid = cert_id
				elif cert_id not in [dcid] + cids:
					cids.append(cert_id)
				else:
					print "Certificate already registered on LB"

		if len(cids) > 0:
			self.lb_service.certificateIds = cids

		return self.lb_service.update()

	def __loop_cert_labels(self, labels, callback):
		for label in labels:
			label_cn = label.keys()[0]
			label_cn_dict = {
				'CN':        label_cn,
				'alt_names': label[label_cn]
			}
			callback(label_cn_dict)

	def update(self):
		self.__get_certificates()
		self.__get_renewal_certificates()
		#print self.lb_service.defaultCertificateId, self.lb_service.certificateIds

		certs_to_retrieve = []
		certs_not_renewal = []

		c_changed, c_add, c_remove, c_update = self.__get_cert_labels()

		if c_changed:

			def check_for_retrieval(cn_dict):
				if cn_dict['CN'] in self.certs_in_rancher:
					cn_dict['id'] = self.certs_in_rancher[cn_dict['CN']]['id']
					if not self.certs_for_renewal.has_key(cn_dict['CN']):
						return certs_not_renewal.append(cn_dict)

				certs_to_retrieve.append(cn_dict)

			self.__loop_cert_labels(c_add, check_for_retrieval)
			self.__loop_cert_labels(c_update, check_for_retrieval)

			# print self.certs_for_renewal
			# print certs_not_renewal
			# print
			# print c_add
			# print
			# print c_update
			# print

			retrieved_certs = self.le.getcerts(certs_to_retrieve)
			# print retrieved_certs
			self.__update_certs_in_rancher(retrieved_certs)
			self.__update_certs_on_lb(c_add + c_update, c_remove)

			print "Set certificates in Rancher & LB!"
		else:
			print "No certificate changes"
