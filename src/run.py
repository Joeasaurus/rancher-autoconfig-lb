#!/usr/bin/env python

import os, sys, time

#from le import LetsEncryptUI, savesync, sslutils_rsa_makekey, tobytes
from RancherCertProxy import RancherCertProxy

try:
	lehome = os.environ["LE_WORK_DIR"]
except:
	print >> sys.stderr, "No $LE_WORK_DIR set!"
	sys.exit(1)

rcp = RancherCertProxy(lehome)
rcp.update()
