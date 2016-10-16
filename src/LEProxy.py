import os, sys
from time import sleep
from le import LetsEncrypt

from ChallengeProxy import R53Proxy
from RPExceptions import *


class LEProxy(LetsEncrypt):
	def __init__(self, home_dir):

		lehome = home_dir
		config = {
			"name": "rancher-autoconfig-lb_le",
			"email": "jme+le@shadowacre.ltd",
			"home": lehome,
			"lock": os.path.join(lehome, "lock"),
			"certs": os.path.join(lehome, "certs"),
			"histfile": os.path.join(lehome, "histfile"),
			"sk": os.path.join(lehome, "sk.pem"),
			"pk": os.path.join(lehome, "pk.pem"),
			"config": os.path.join(lehome, "config"),
			"debug": False,
			"url": os.environ["CA"],
			#"https://acme-staging.api.letsencrypt.org/directory"
			#"https://acme-v01.api.letsencrypt.org/directory"
			"register": True,
			"ecdsa": False
		}

		self.dns_auth = R53Proxy()
		super(LEProxy, self).__init__(config)

		try:
			self.method_register("https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf " + self.config["email"])
		except Exception, e:
			if str(e) == "ERR_INUSE":
				print "Registration already performed, continuing.."

	def __challenge_domains(self, domain_list):
		challenge_pairs = []

		if not len(domain_list):
			raise EmptyDomain("domain_list is empty!" + domain_list)

		challenges = [self.method_domainchallenge(name) for name in domain_list]

		challenge_pairs = [
			[ c["dns-01"][1].replace("'","").split(":")[0],
			  c["dns-01"][1].replace("'","").split(":")[1] ]
			for c in challenges
		]

		#print challenges
		# for cp in challenge_pairs:
		# 	print cp[0] + " ----> " + cp[1]

		if self.dns_auth.add_challenge(challenge_pairs):
			for d in domain_list:
				self.method_domainconfirm(d + " dns-01")

		return challenge_pairs

	def getcerts(self, certs):
		cert_index = 0

		for cert_list in certs[:]:

			domain_name   = cert_list['CN']
			domain_concat = domain_name + " " + " ".join(cert_list['alt_names'])
			domain_list   = [cert_list['CN']] + cert_list['alt_names']

			challenged = self.__challenge_domains(domain_list)
			if challenged:
				cert = self.method_certificateget(domain_concat)
				cert_list['ssl'] = cert
			else:
				cert_list['ssl'] = False

			certs[cert_index] = cert_list
			cert_index += 1

		return certs
