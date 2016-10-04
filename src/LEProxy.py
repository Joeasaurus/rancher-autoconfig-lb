import os
from time import sleep
import le
LEUI = le.LetsEncryptUI


class LEProxy(LEUI):
	def __init__(self, home_dir, dnsproxy):
		self.dns_auth = dnsproxy

		lehome = home_dir

		config = {
			"name": "rancher-atuoconfig-lb_le",
			"email": "jme+le@shadowacre.ltd",
			"home": lehome,
			"lock": os.path.join(lehome, "lock"),
			"certs": os.path.join(lehome, "certs"),
			"histfile": os.path.join(lehome, "histfile"),
			"sk": os.path.join(lehome, "sk.pem"),
			"pk": os.path.join(lehome, "pk.pem"),
			"config": os.path.join(lehome, "config"),
			"debug": False,
			"url": "https://acme-staging.api.letsencrypt.org/directory", #"https://acme-v01.api.letsencrypt.org/directory"
			"register": True,
			"ecdsa": False
		}
		self.config = config


		if not os.path.exists(config["home"]):
				os.mkdir(config["home"])

		#create directory for certificates
		if not os.path.exists(config["certs"]):
				os.mkdir(config["certs"])

		#create lock file
		if not os.path.exists(config["lock"]):
				le.savesync(config["lock"], le.tobytes(" "))

		#create RSA master keys
		if not os.path.exists(config["sk"]):
				tmpsk = "%s.tmp" % (config["sk"])
				tmppk = "%s.tmp" % (config["pk"])
				le.sslutils_rsa_makekey(tmpsk, tmppk, 3072)
				os.rename(tmppk, config["pk"])
				os.rename(tmpsk, config["sk"])

		super(LEProxy, self).__init__()

	def getcerts(self, names):
		for cert_list in names:
			domain_name   = cert_list.keys()[0]
			domain_concat = domain_name + " " + " ".join(cert_list[domain_name])
			domain_list   = domain_concat.split(" ")
			challenges    = [self.method_domainchallenge(name) for name in domain_list]

			challenge_pairs = [
				[ c["dns-01"][1].replace("'","").split(":")[0],
				  c["dns-01"][2] ]
				for c in challenges
			]

			#print challenges
			for cp in challenge_pairs:
				print cp[0] + " ----> " + cp[1]

			if self.dns_auth.add_challenge(challenge_pairs):
				print "Sleeping to let LE catch up..."; sleep(40)
				for d in domain_list:
					print d
					self.method_domainconfirm(d + " dns-01")

				# cert = self.method_certificateget(domain_concat)
				# print cert

			# Set challenges in r53
			# Confirm them with LE
			# request a certificate for them
			# store the cert
