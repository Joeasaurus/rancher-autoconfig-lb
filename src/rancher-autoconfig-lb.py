#!/usr/bin/env python

import os, sys

#from le import LetsEncryptUI, savesync, sslutils_rsa_makekey, tobytes
from ChallengeProxy import R53Proxy
from LEProxy import LEProxy
from RancherProxy import RancherProxy

if __name__ == '__main__':
	try:
		lehome = os.path.join(os.environ["HOME"], ".le_home")
	except:
		print >> sys.stderr, "No $HOME set!"
		sys.exit(1)

	le = LEProxy(lehome, R53Proxy())
	rp = RancherProxy(le)

	try:
		rp.update()
	except Exception, e:
		print >> sys.stderr, 'System error: ' + str(e)

		# time.sleep(10)


#
#
#
#   ^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$
#   alt_names = []
#
#						 if len(title_split) > 1:
#							 alt_names = [title_split[1].split(',')]
#							 alt_names = alt_names[:-1] if alt_names[-1] == '' else alt_names
#
#			 {
#	 "cert": "string",
#	 "certChain": "string",
#	 "description": "string",
#	 "key": "string",
#	 "name": "string"
# }
