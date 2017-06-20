#!/usr/bin/env python

import os, sys, time

#from le import LetsEncryptUI, savesync, sslutils_rsa_makekey, tobytes
from CertUpdater import CertUpdater

lehome = os.environ.get("LE_WORK_DIR", "./working")

cu = CertUpdater(lehome)
cu.update()
