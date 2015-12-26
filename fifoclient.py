#!/usr/bin/python3

import os
import sys
import hmac

FIFOHOOK_HOME = '/tmp/fifohook'
#FIFOHOOK_HOME = '.'

def connect(name, key, act=''):
    fhfile = os.path.join(FIFOHOOK_HOME, '%s.fifo' % name)
    with open(fhfile, 'r') as fh:
        msg = fh.read().strip()
    digest = hmac.new(key.encode(), msg.encode(), 'sha256').hexdigest()
    with open(fhfile, 'w') as fh:
        print(digest, act, file=fh)

name = sys.argv[1]
key = sys.argv[2]
act = ''
if len(sys.argv) >= 4:
    act = sys.argv[3]

connect(name, key, act)
