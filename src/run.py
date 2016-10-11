#!/usr/bin/env python

import os, sys, time

#from le import LetsEncryptUI, savesync, sslutils_rsa_makekey, tobytes
from RancherProxy import RancherProxy
from RancherCertProxy import RancherCertProxy

try:
	lehome = os.environ["LE_WORK_DIR"]
except:
	print >> sys.stderr, "No $LE_WORK_DIR set!"
	sys.exit(1)

rp = RancherProxy()
rcp = RancherCertProxy(lehome)

while True:
	rp.update()
	rcp.update()
  	time.sleep(20)


#
#
#
#   ^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$
