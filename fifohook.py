#!/usr/bin/python3

import os
import sys
import uuid
import string
import random
import logging
import hmac
import subprocess

logging.basicConfig(format='[%(levelname)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger('fifohook')

FIFOHOOK_HOME = '/tmp/fifohook'
#FIFOHOOK_HOME = '.'

if not os.path.isdir(FIFOHOOK_HOME):
    if os.path.exists(FIFOHOOK_HOME):
        logger.fatal("%s is not a folder, abort" % FIFOHOOK_HOME)
        exit(1)
    os.mkdir(FIFOHOOK_HOME)

def randstr(k):
    return ''.join(random.sample(string.ascii_letters, k))

def hash_check(key, msg, digest):
    return hmac.compare_digest(hmac.new(key.encode(), msg.encode(), 'sha256').hexdigest(), digest)

class FIFOHook:
    def __init__(self, name, command, key):
        self.name = name
        self.command = command
        self.key = key
        self.fhfile = os.path.join(FIFOHOOK_HOME, '%s.fifo' % self.name)
        self._prepare()

    def _prepare(self):
        if not os.path.exists(self.fhfile):
            os.mkfifo(self.fhfile)
        os.chmod(self.fhfile, 0o666)

    def __repr__(self):
        return '<FIFOHook "%s">' % self.name

    def run(self):
        while True:
            with open(self.fhfile, 'w') as fh:
                msg = randstr(16)
                print(msg, file=fh)
                fh.close()
            with open(self.fhfile, 'r') as fh:
                resp = fh.read().strip().split()
            digest = resp[0]
            if hash_check(self.key, msg, digest):
                logger.info("authenticated")
                if len(resp) >= 2 and resp[1] == 'close':
                    logger.info("server closed")
                    break
                self._execute()
            else:
                logger.info("failed")
    
    def _execute(self):
        ret = subprocess.call(self.command)
        logger.info("command run and returned %d" % ret)

name = sys.argv[1]
key = sys.argv[2]
command = sys.argv[3]

FIFOHook(name, command, key).run()
