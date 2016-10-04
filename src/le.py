#!/usr/bin/env python
#20160812
#Jan Mojzis
#Public Domain

#tobytes.py
def tobytes(x):
		"""
		python2/3 compatible conversion to bytes from str/bytes
		"""

		#python2 unicode-hack
		try:
				if isinstance(x, unicode):
						x = str(x)
		except NameError:
				pass

		if isinstance(x, bytes):
				return x
		if isinstance(x, str):
				r = []
				for ch in x:
						r.append(ord(ch))
				return bytes(r)
		raise TypeError("tobytes() accepts only <type 'str'> or <class 'bytes'> not %s" % (type(x)))

#tostr.py
def tostr(x):
		"""
		python2/3 compatible conversion to str from str/bytes
		"""
		if isinstance(x, str):
				return x
		if isinstance(x, bytes):
				r = ""
				if len(x) > 0 and isinstance(x[0], int):
						for ch in x: r += chr(ch)
				else:
						for ch in x: r += ch
				return r
		raise TypeError("tostr() accepts only <type 'str'> or <class 'bytes'> not %s" % (type(x)))

#tojson.py
import json

def tojson(x):
		"""
		python2/3 compatible conversion to json string
		"""

		return tobytes(json.dumps(x))

#tobase64.py
import base64

def tobase64(x):
		"""
		python2/3 compatible conversion to urlsafe base64 encoding
		"""

		return tostr(base64.urlsafe_b64encode(tobytes(x))).replace('=', '')

#savesync.py
import os

def savesync(fn, data):
		"""
		"""

		f = open(fn, 'wb')
		f.write(data)
		os.fsync(f.fileno())
		f.close()

#httpquery.py
try:
		from urllib.request import urlopen
		from urllib.request import Request
		from urllib.error   import HTTPError
except ImportError:
		from urllib2 import urlopen
		from urllib2 import Request
		from urllib2 import HTTPError

def httpquery(url = "", data = None, headers = {}, timeout = 60):
		"""
		python2/3 compatible HTTP/HTTPS client
		"""

		try:
				req = Request(url, data = data, headers = headers)
				r = urlopen(req, timeout = timeout)
		except HTTPError as e:
				r = e
		except Exception as e:
				return { "status": -1, "error": str(e) }

		headers = {}
		for h, v in r.info().items():
				headers[h.lower()] = v

		return {
				"status": r.code,
				"error": "http error %d %s" % (r.code, r.msg),
				"headers": headers,
				"body": r.read()
		}


#subprocessrun.py
import os, sys
try:
		import cPickle as pickle
except ImportError:
		import pickle

def subprocessrun(func, *args, **kwds):
		"""
		python2/3 compatible function for runing functions in separate process
		"""
		fromchild, tochild = os.pipe()
		pid = os.fork()
		if (pid == 0):
				#child
				os.close(fromchild)
				try:
						r = func(*args, **kwds)
						status = 0
				except Exception as e:
						status = 111
						r = e
				with os.fdopen(tochild, 'wb') as f:
						try:
								pickle.dump(r, f, pickle.HIGHEST_PROTOCOL)
						except pickle.PicklingError as e:
								status = 111
								pickle.dump(e, f, pickle.HIGHEST_PROTOCOL)
						pickle.dump(r, f, pickle.HIGHEST_PROTOCOL)
				sys.exit(status)
		#parent
		os.close(tochild)
		with os.fdopen(fromchild, 'rb') as f:
				try:
						result = pickle.load(f)
				except EOFError as e:
						result = None

		#wait for child
		(_pid, status) = os.waitpid(pid, 0)

		#success
		if status == 0: return result

		#failure - function in subprocess raised an exception
		if result: raise result

		#failure - process killed or exited with status > 0
		st = os.WEXITSTATUS(status)
		if os.WTERMSIG(status) > 0:
				raise Exception("subprocess was killed by signal %d" % (os.WTERMSIG(status)))
		else:
				raise Exception("subprocess exited with status %d" % (os.WEXITSTATUS(status)))

#sslutils.py
import subprocess
import binascii
import os, stat

def sslutils_x509_dertopem(x = ""):
		"""
		Conversion from DER to PEM format
		XXX TODO - remove dependency on openssl
		"""

		if x.find("BEGIN CERTIFICATE") != -1:
				return x

		cmd = ['openssl', 'x509', '-inform', 'der', '-outform', 'pem']
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
		ret = p.communicate(x)[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		return ret

def sslutils_x509_pemtoder(x = ""):
		"""
		Conversion from PEM to DER format
		XXX TODO - remove dependency on openssl
		"""

		if x.find("BEGIN CERTIFICATE") == -1:
				return x

		cmd = ['openssl', 'x509', '-inform', 'pem', '-outform', 'der']
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
		ret = p.communicate(x)[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		return ret


def sslutils_x509_pemtotext(x = ""):
		"""
		Conversion from PEM format to text form
		XXX TODO - remove dependency on openssl
		"""

		cmd = ['openssl', 'x509', '-inform', 'pem', '-noout', '-text']
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
		ret = p.communicate(x)[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		return ret

def _sslutils_req(domains = [], cfg = "", key = "", ecdsa = False):
		"""
		Create new RSA key and simple CSR request.
		XXX TODO - remove dependency on openssl
		"""

		if len(domains) == 0:
				raise Exception("no domains")

		i = 1
		subject = "/CN="
		config  = "[req]\n"
		config += "distinguished_name = req_distinguished_name\n"
		config += "req_extensions=v3_req\n"
		config += "[req_distinguished_name]\n"
		config += "[v3_req]\n"
		config += "basicConstraints=CA:FALSE\n"
		config += "keyUsage=nonRepudiation,digitalSignature,keyEncipherment\n"
		config += "subjectAltName=@alt_names\n"
		config += "[alt_names]\n"

		for domain in domains:
				if domain.find('/') >= 0:
						raise Exception("bad domain %s" % (domain))
				if domain.find('*') >= 0:
						raise Exception("bad domain %s" % (domain))
				config += "DNS.%d=%s\n" % (i, domain)
				if i == 1:
						subject += domain
				i += 1

		savesync(cfg, tobytes(config))

		if ecdsa:
				#create ECDSA key
				_sslutils_ecdsa_makekey(key)
		else:
				#create RSA key
				_sslutils_rsa_makekey(key, "", 2048)

		#create request
		cmd = ['openssl', 'req', '-sha256', '-nodes', '-subj', subject, '-key', key, '-new', '-outform', 'der', '-config', cfg]
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
		ret = p.communicate('')[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		return ret

def sslutils_req(domains = [], cfg = "", key = "", ecdsa = False):
		"""
		SECURITY: Secret key operation is isolated in separate process.
		"""

		return subprocessrun(_sslutils_req, domains, cfg, key, ecdsa)



def _sslutils_rsa_signsha256(key, data):
		"""
		Sign SHA256('data') using RSA key 'key'.
		XXX TODO - remove dependency on openssl
		"""

		cmd = ['openssl', 'dgst', '-sha256', '-sign', key]
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
		ret = p.communicate(data)[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		return ret

def sslutils_rsa_signsha256(key, data):
		"""
		SECURITY: Secret key operation is isolated in separate process.
		"""

		return subprocessrun(_sslutils_rsa_signsha256, key, data)


def _sslutils_rsa_makekey(sk = "", pk = "", size = 2048):
		"""
		Create RSA key
		XXX TODO - remove dependency on openssl
		"""

		cmd = ['openssl', 'genrsa', '-rand', '/dev/urandom', str(size)]
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
		data = p.communicate("")[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		f = open(sk, "wb")
		os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR)
		f.write(data)
		os.fsync(f.fileno())
		f.close()

		if not pk:
				return

		cmd = ['openssl', 'rsa', '-in', sk, '-pubout']
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
		data = p.communicate("")[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		f = open(pk, "wb")
		os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
		f.write(data)
		os.fsync(f.fileno())
		f.close()

def _sslutils_ecdsa_makekey(sk = ""):
		"""
		Create ECDSA key
		XXX TODO - remove dependency on openssl
		"""

		cmd = ['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-rand', '/dev/urandom']
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
		data = p.communicate("")[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))
		f = open(sk, "wb")
		os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR)
		f.write(data)
		os.fsync(f.fileno())
		f.close()



def sslutils_rsa_makekey(sk = "", pk = "", size = 2048):
		"""
		SECURITY: Secret key operation is isolated in separate process.
		"""

		return subprocessrun(_sslutils_rsa_makekey, sk, pk, size)


def sslutils_rsa_getpk(pkfn):
		"""
		Import RSA public key and return (exponent, modulus)
		XXX temporary dirty HACK XXX
		XXX TODO - remove dependency on openssl
		"""

		cmd = ['openssl', 'rsa', '-modulus', '-text', '-pubin', '-noout', '-in', pkfn]
		p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
		data = p.communicate('')[0]
		if (p.returncode != 0):
				raise Exception("%s: failed" % (" ".join(cmd)))

		for line in tostr(data).split('\n'):
				if len(line) < 10:
						continue
				if line[0:9] == "Exponent:":
						exponent = line.split(')')[0].split('(')[1][2:]
				if line[0:8] == "Modulus=":
						modulus = line[8:]

		if (len(exponent) % 2):
				exponent = "0" + exponent

		exponent = binascii.unhexlify(exponent)
		modulus = binascii.unhexlify(modulus)
		return (exponent, modulus)

#jwk.py
import hashlib


def jwk(e, n):
		"""
		Create JSON Web Key from RSA exponent end modulus
		"""

		return { "e": tobase64(e), "kty": "RSA", "n": tobase64(n) }


def jwkthumb(e, n):
		"""
		JSON Web Key Thumbprint SHA256 from RSA exponent end modulus
		"""

		js = '{"e":"%s","kty":"RSA","n":"%s"}' % (tobase64(e), tobase64(n))
		return tobase64(hashlib.sha256(tobytes(js)).digest())

#main.py
import getopt, os, time, fcntl

class LetsEncryptUI(object):
		"""
		XXX TODO
		Class which implements user friendly
		shell for LetsEncrypt certificate authority
		"""

		#colors for tty run XXX TODO
		ENDC = '\033[0m'
		DEBUG = '\033[90m'
		TRACEBACK = '\033[33m'
		INFO = '\033[93m' #yellow
		SUCCESS = '\033[94m' #blue

		def __init__(self):

				#load RSA public-key, format it to JWK and make JWK thumbprint
				(e, n) = sslutils_rsa_getpk(self.config["pk"])
				self.jwk = jwk(e, n)
				self.jwkthumb = jwkthumb(e, n)

				#ACME Replay-Nonce
				self.acmenonce = None

				#send query for ACME url's for new-authz, new-cert, revoke-cert, ..
				self.acmedirectory = self._directory()

				try:
					if self.config['register']:
						self.method_register("https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf " + self.config["email"])
				except:
					pass

		def _lock(self, fn = ""):
				"""
				"""

				try:
						fd = os.open(self.config["lock"], os.O_RDWR)
						fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

				except Exception as e:
						self._log("Exception: %s" % (str(e)), self.TRACEBACK)
						sys.exit(1)

		def _log(self, text = "", color = None):
				"""
				"""

				if not self.config["debug"]:
						if color == self.DEBUG:
								return
						if color == self.SUCCESS:
								return

				if color:
						text = color + text + self.ENDC

				f = sys.stdout
				f.write(text)
				f.write("\n")
				f.flush()

		def _httpquery(self, url = "", data = None, headers = {}, timeout = 60):
				"""
				"""

				self._log("query = %s %s" % (url, str(data)), self.DEBUG)

				response = httpquery(url = url, data = data, headers = headers, timeout = timeout)

				self._log("response = %s" % (str(response)), self.DEBUG)

				if response["status"] != -1:
						#get ACME nonce from HTTP header Replay-Nonce
						self.acmenonce = response["headers"]["replay-nonce"]

						#parse JSON body
						if "content-type" in response["headers"]:
								if response["headers"]["content-type"].lower() == "application/json":
										response["jsonbody"] = json.loads(tostr(response["body"]))
								if response["headers"]["content-type"].lower() == "application/problem+json":
										response["jsonbody"] = json.loads(tostr(response["body"]))
				return response

		def _directory(self):
				"""
				Sends ACME query and gets urls for new-authz, new-cert, revoke-cert, ..
				"""

				response = self._httpquery(self.config["url"])
				if response["status"] != 200:
						raise Exception("ACME query for directory failed: %s" % response["error"])
				return response["jsonbody"]


		def jws(self, payload = {}):
				"""
				JSON Web Signature construction.
				"""

				#create header
				header = {}
				header["alg"] = "RS256"
				header["jwk"] = self.jwk

				#payload
				payloaddata = tobase64(tojson(payload))

				#protected
				protected = {}
				protected["nonce"] = tostr(self.acmenonce)
				protecteddata = tobase64(tojson(protected))

				signdata = "%s.%s" % (protecteddata, payloaddata)
				signature = sslutils_rsa_signsha256(self.config["sk"], tobytes(signdata))
				signature = tobase64(signature)

				return tojson({"header":header, "payload": payloaddata, "protected": protecteddata, "signature":signature})


		def method_register(self, arg):
				"""
				Methods registers master RSA public-key, email, [telephone], ...
				"""

				if not len(arg):
						self.printdoc(self.method_register)
						raise Exception("usage: register agreement-url email [telephone]")

				opts = arg.split(" ")
				if len(opts) < 2:
						self.printdoc(self.method_register)
						raise Exception("usage: register agreement-url email [telephone]")

				argeement = opts[0]

				contacts = ["mailto:%s" % (opts[1])]
				if len(opts) > 2:
						contacts.append("tel:%s" % (opts[2]))

				payload = {
						"resource": "new-reg",
						"contact": contacts,
						"agreement": argeement,
				}

				headers = {'content-type': 'application/json'}
				response = self._httpquery(self.acmedirectory["new-reg"], self.jws(payload), headers)
				if response["status"] != 201:
						if "jsonbody" in response:
								raise Exception(response["jsonbody"])
						raise Exception(response["error"])



		def method_domainchallenge(self, domain):
				"""
				Method requests challenge for domain authentication.
				Client than creates HTTP url:
				http://{domain}/.well-known/acme-challenge/{token_from_challenge}
				and calls 'domainconfirm {domain}' to finish authentication.
				"""

				if not len(domain):
						raise Exception("usage: domainchallenge domain")

				#challenge filename
				#support for http-01
				chl_http_dst = os.path.join(self.config["certs"], "%s.http-01.chl" % (domain))
				chl_http_tmp = "%s.tmp" % (chl_http_dst)
				#support for dns-01
				chl_dns_dst = os.path.join(self.config["certs"], "%s.dns-01.chl" % (domain))
				chl_dns_tmp = "%s.tmp" % (chl_dns_dst)

				if not os.path.exists(chl_http_dst) or not os.path.exists(chl_dns_dst):
						payload = {
								"resource": "new-authz",
								"identifier": {
										"type": "dns",
										"value": domain
								}
						}
						headers = {'content-type': 'application/json'}
						response = self._httpquery(self.acmedirectory["new-authz"], self.jws(payload), headers)
						if response["status"] != 201:
								if "jsonbody" in response:
										raise Exception("ACME query failed: %s" % (response["jsonbody"]))
								else:
										raise Exception("ACME query failed: %s" % (response["error"]))

						for x in response["jsonbody"]["challenges"]:
								if x["type"] == "http-01":
										#support for http-01
										keyauth = "%s.%s" % (x["token"], self.jwkthumb)
										content = x["token"]
										data = "%s\nhttp://%s/.well-known/acme-challenge/%s\n%s\n" % (x["uri"], domain, content, keyauth)
										savesync(chl_http_tmp, tobytes(data))
										os.rename(chl_http_tmp, chl_http_dst)
								if x["type"] == "dns-01":
										#support for dns-01
										keyauth = "%s.%s" % (x["token"], self.jwkthumb)
										content = tobase64(hashlib.sha256(tobytes(keyauth)).digest())
										data = "%s\n'_acme-challenge.%s:%s\n%s\n" % (x["uri"], domain, content, keyauth)
										savesync(chl_dns_tmp, tobytes(data))
										os.rename(chl_dns_tmp, chl_dns_dst)

				#http-01
				data = {"http-10": open(chl_http_dst, 'r').read().split('\n')}
				# self._log("http-01:\nURL=%s\nCONTENT=%s\n" % (data[1], data[2]), self.DEBUG)

				#dns-01
				data["dns-01"] = open(chl_dns_dst, 'r').read().split('\n')
				return data


		def method_domainconfirm(self, domain):
				"""
				Method confirms that url:
				http://{domain}/.well-known/acme-challenge/{token_from_challenge}
				is created and sends information to server.
				Server will validate the url to complete domain authentication.
				"""

				if not len(domain):
						self.printdoc(self.method_domainconfirm)
						raise Exception("usage: domainconfirm domain [type]")

				domains = []
				tmp = domain.split(" ")
				for d in tmp:
						if len(d):
								domains.append(d)
				domain = domains[0]

				#challenge filename
				chl_http_dst = os.path.join(self.config["certs"], "%s.http-01.chl" % (domain))
				chl_dns_dst = os.path.join(self.config["certs"], "%s.dns-01.chl" % (domain))

				if (len(domains) > 1):
						if domains[1] == "http":
								typ = "http-01"
								chl_dst = chl_http_dst
						elif domains[1] == "dns":
								typ = "dns-01"
								chl_dst = chl_dns_dst
						elif domains[1] == "dns-01":
								typ = "dns-01"
								chl_dst = chl_dns_dst
						else:
								raise Exception("type must be dns or http")
				else:
						typ = "http-01"
						chl_dst = chl_http_dst

				if not os.path.exists(chl_dst):
						raise Exception("challenge not exist, try 'challenge %s' first" % (domain))

				data = open(chl_dst, 'r').read().split('\n')
				url = data[0]
				keyauth = data[2]
				print data

				i = 0
				timeouts = [10, 100, 1000]
				for timeout in timeouts:
						response = self._httpquery(url)
						if response["status"] != 202:
								if "jsonbody" in response:
										raise Exception("ACME query failed: %s" % (response["jsonbody"]))
								else:
										raise Exception("ACME query failed: %s" % (response["error"]))

						if response["jsonbody"]["status"] == 'valid':
								os.unlink(chl_http_dst)
								os.unlink(chl_dns_dst)
								return

						if response["jsonbody"]["status"] == 'invalid':
								os.unlink(chl_http_dst)
								os.unlink(chl_dns_dst)
								raise Exception("%s - try again 'challenge %s'" % (response["jsonbody"]["error"], domain))

						if response["jsonbody"]["status"] != 'pending':
								raise Exception("query failed: bad status %s" % (response["jsonbody"]["status"]))

						if i == 0:
								payload = {
										"resource": "challenge",
										"type": typ,
										"keyAuthorization": keyauth,
								}

								headers = {'content-type': 'application/json'}
								response = self._httpquery(url, self.jws(payload), headers)
								if response["status"] != 202:
										if "jsonbody" in response:
												raise Exception("ACME query failed: %s" % (response["jsonbody"]))
										else:
												raise Exception("ACME query failed: %s" % (response["error"]))
						time.sleep(timeout)
						i += 1

				raise Exception("Request pending, try it again later")

		def _parse_im_url(self, pem):
				"""
				Parse intermediate cert URL from X509 certificate
				XXX - it's hack, not serious parser
				"""

				data = tostr(sslutils_x509_pemtotext(pem))
				for line in data.split('\n'):
						line = line.strip()
						if line[0:10].lower() != "ca issuers":
								continue
						line = line.split(':', 1)[1]
						return line

		def method_certificateget(self, domain):
				"""
				Method creates new RSA key, new CSR (Certificate Signing Request),
				server signs the request and returns x509 certificate.
				Domain (CN) in the request must be authenticated using
				methods domainchallenge and domainconfirm.
				"""

				if not len(domain):
						self.printdoc(self.method_certificateget)
						raise Exception("usage: certificateget domain1 [domain2] ...")

				domains = []
				tmp = domain.split(" ")
				for d in tmp:
						if len(d):
								domains.append(d)

				tm = time.strftime("%Y%m%d%H%M%S", time.localtime())
				dn = os.path.join(self.config["certs"], domains[0])
				key_tmp = "%s.%s.key.tmp" % (dn, tm)
				key_bak = "%s.%s.key.bk"  % (dn, tm)
				key_dst = "%s.key"  % (dn)
				crt_tmp = "%s.%s.crt.tmp" % (dn, tm)
				crt_bak = "%s.%s.crt.bk"  % (dn, tm)
				crt_dst = "%s.crt"  % (dn)
				im_tmp = "%s.%s.im.tmp" % (dn, tm)
				im_bak = "%s.%s.im.bk"  % (dn, tm)
				im_dst = "%s.im"  % (dn)
				cfg	 = "%s.%s.conf" % (dn, tm)
				csr = tobase64(sslutils_req(domains, cfg, key_tmp, self.config["ecdsa"]))

				payload = {
						"resource": "new-cert",
						"csr": csr,
				}

				headers = {"Accept": "application/pkix-cert", 'content-type': 'application/json'}
				response = self._httpquery(self.acmedirectory["new-cert"], self.jws(payload), headers)
				if response["status"] != 201:
						os.unlink(key_tmp)
						if "jsonbody" in response:
								raise Exception(response["jsonbody"])
						raise Exception(response["error"])
				try:
						#XXX TODO - remove this try-except
						pem = sslutils_x509_dertopem(response["body"])

						#get intermediate cert.
						imurl = self._parse_im_url(pem)
						impem = httpquery(imurl)
						if impem["status"] != 200:
								raise Exception("unable to download intermediate certificate from %s: %s" % (imurl,impem["error"]))

						savesync(crt_tmp, pem)
						savesync(im_tmp, sslutils_x509_dertopem(impem["body"]))
				except:
						os.unlink(key_tmp)
						if os.path.exists(crt_tmp):
								os.unlink(crt_tmp)
						if os.path.exists(im_tmp):
								os.unlink(im_tmp)
						raise

				os.link(key_tmp, key_bak)
				os.rename(key_tmp, key_dst)
				os.link(crt_tmp, crt_bak)
				os.rename(crt_tmp, crt_dst)
				os.link(im_tmp, im_bak)
				os.rename(im_tmp, im_dst)

				self._log("KEY=%s\nCERT=%s\nIM=%s\n" % (key_dst, crt_dst, im_dst), self.INFO)


		def method_certificaterevokeold(self, dummy):
				"""
				Method revokes old x509 certificates
				"""

				certs = []
				for fn in os.listdir(self.config["certs"]):
						if fn[-6:] == "crt.bk":
								st = os.stat(os.path.join(self.config["certs"], fn))
								if st.st_nlink == 1:
										certs.append(fn[:-7])

				if not len(certs):
						raise Exception("can't revoke certificates, no non-active certificate found! Try to request new certificate and after that revoke the old one.")

				for domain in certs:
						fnc  = os.path.join(self.config["certs"], "%s.crt.bk" % (domain))
						fncr = os.path.join(self.config["certs"], "%s.crt.revoked" % (domain))
						fnk  = os.path.join(self.config["certs"], "%s.key.bk" % (domain))
						fnkr = os.path.join(self.config["certs"], "%s.key.revoked" % (domain))
						fni  = os.path.join(self.config["certs"], "%s.im.bk" % (domain))
						fnir = os.path.join(self.config["certs"], "%s.im.revoked" % (domain))

						pem = open(fnc, 'r').read()
						der = sslutils_x509_pemtoder(pem)

						payload = {
								"resource": "revoke-cert",
								"certificate": tobase64(der),
						}

						headers = {'content-type': 'application/json'}
						response = self._httpquery(self.acmedirectory["revoke-cert"], self.jws(payload), headers)
						if response["status"] != 200:
								if "jsonbody" in response:
										raise Exception("ACME query failed: %s" % (response["jsonbody"]))
								else:
										raise Exception("ACME query failed: %s" % (response["error"]))
						os.rename(fnc, fncr)
						os.rename(fnk, fnkr)
						if os.path.exists(fni):
								os.rename(fni, fnir)


usagetext = """
 name:
   letsencryptshell - shell style commandline client for LetsEncrypt

 syntax:
   letsencryptshell [options]

 options:
   -h	 (optional): print usage
   -d	 (optional): debug mode
   -u url (optional): ACME directory (default: https://acme-v01.api.letsencrypt.org/directory)
   -e	 (optional): create ECDSA key + cert instead of RSA
"""


def usage(x = ""):
		"""
		Print usage.
		XXX TODO
		"""
		print(usagetext)
		sys.exit(100)

#program entry point
if __name__ == "__main__":


		#create config structure
		config = {}
		config["name"] = "LetsEncryptShell"
		config["home"] = os.path.join(os.environ["HOME"], ".letsencryptshell")
		config["lock"] = os.path.join(os.environ["HOME"], ".letsencryptshell", "lock")
		config["certs"] = os.path.join(os.environ["HOME"], ".letsencryptshell", "certs")
		config["histfile"] = os.path.join(config["home"], "histfile")
		config["sk"] = os.path.join(config["home"], "sk.pem")
		config["pk"] = os.path.join(config["home"], "pk.pem")
		config["config"] = os.path.join(config["home"], "config")
		config["debug"] = True #XXX TODO - debug is currently default
		config["url"] = "https://acme-v01.api.letsencrypt.org/directory"
		#config["url"] = "https://acme-staging.api.letsencrypt.org/directory"
		config["register"] = False
		config["ecdsa"] = False

		#parse program parameters
		try:
				options, arguments = getopt.getopt(sys.argv[1:], 'u:hde')
		except:
				#bad option
				usage("Error: Bad option.")
				sys.exit(100)

		# process options
		for opt, val in options:
				if opt == "-h":
						usage()
						sys.exit(100)
				if opt == "-u":
						config["url"] = val
				if opt == "-r":
						config["register"] = True
				if opt == "-d":
						config["debug"] = True
				if opt == "-e":
						config["ecdsa"] = True


		#home directory
		if not "HOME" in os.environ:
				print("$HOME not set!!")
				sys.exit(111)

		#create home directory
		if not os.path.exists(config["home"]):
				os.mkdir(config["home"])
		#create directory for certificates
		if not os.path.exists(config["certs"]):
				os.mkdir(config["certs"])
		#create lock file
		if not os.path.exists(config["lock"]):
				savesync(config["lock"], tobytes(" "))
		#create RSA master keys
		if not os.path.exists(config["sk"]):
				tmpsk = "%s.tmp" % (config["sk"])
				tmppk = "%s.tmp" % (config["pk"])
				sslutils_rsa_makekey(tmpsk, tmppk, 3072)
				os.rename(tmppk, config["pk"])
				os.rename(tmpsk, config["sk"])

		ui = LetsEncryptUI(config)
		sys.exit(ui.serve())
