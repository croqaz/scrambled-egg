#!/usr/bin/env python

import os
import subprocess
import logging as log
from time import clock
from collections import OrderedDict

from Crypto import Random
from Crypto.Random import random
from Crypto.Hash import MD5

_SCRAMBLE_D = {'ROT13':'R', 'ZLIB':'ZL', 'BZ2':'BZ'}
_ENC = OrderedDict([('AES', 'AES'), ('Blowfish', 'B'), ('ARC2', 'ARC'), ('CAST', 'CA'), ('DES3', 'D')])
_ENCODE_D = {'Base64 Codec':'64', 'Base32 Codec':'32', 'HEX Codec':'H', 'Json':'JS', 'XML':'XML'}

PASSED = True
TESTS = 3

#

def RandText():
    # Returns a random piece of text.
    words = random.randrange(1, 99)
    txt = []
    for i in range(words):
        # Word length.
        L = random.randrange(1, 99)
        txt.append(Random.new().read(L))
    return b' '.join(txt)

def RandPassword():
    # Returns a random password between 1 and 196.
    L = random.randrange(1, 19)
    pwd = []
    for i in range(L):
        pwd.append(random.choice('0123456456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'))
    pwd = b''.join(pwd)
    L = len(pwd)
    return pwd

def splitthousands(s, sep=','):
    # Splits large numbers with commas.
    s = str(s)
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

log.basicConfig(level=10, format='%(asctime)s %(levelname)-10s %(message)s', datefmt='%y-%m-%d %H:%M:%S', filename='Testing3_Log.Log', filemode='w')
console = log.StreamHandler() ; console.setLevel(10) ; log.getLogger('').addHandler(console) # Print + write log.
log.info('Preparing to run %i tests.\n' % TESTS)

for f in range(1, TESTS+1):
    #
    SPEEDs = {}
    SIZEs = {}
    log.info('Test number [%i] ...' % f)
    #
    data = RandText()
    open('test.data', 'wb').write(data)
    L = len(data)
    H = MD5.new(data).hexdigest()
    del data
    #
    for pre in _SCRAMBLE_D:
        for enc in _ENC:
            for post in _ENCODE_D:
                #
                post = post.replace(' Codec', '')
                #
                ti = clock()
                #
                # Generate random password.
                pwd = RandPassword()
                #
                # Encrypt
                subprocess.Popen(['python', '-B', 'scrambled_egg.py', '-i', 'test.data', '-o', 'output.dat', '-p', pwd,
                    '--pre', pre, '--enc', enc, '--post', post]).wait()
                _enc = open('output.dat', 'rb').read()
                #
                # Decrypt
                subprocess.Popen(['python', '-B', 'scrambled_egg.py', '-i', 'output.dat', '-o', 'decrypt.dat', '-p', pwd,
                    '--decrypt', 'true']).wait()
                _dec = open('decrypt.dat', 'rb').read()
                #
                try:
                    L_check = len(_dec)
                    H_check = MD5.new(_dec).hexdigest()
                except:
                    L_check = None ; H_check = None
                    log.error('Error on test `%s %s %s`!' % (pre, enc, post))
                    log.debug('Txt len: %i' % L)
                    log.debug('Pwd: %s' % pwd)
                    log.debug(' '.join(s.error.split()))
                    exit(1)
                #
                # Checking.
                if L_check != L or H_check != H:
                    log.error('Error! The result is not the same after encryption/ decryption with `%s %s %s`!\n' % (pre, enc, post))
                    log.debug('Original len: %s ; Decrypt len: %s' % (L, L_check))
                    log.debug('Original hash: %s ; Decrypt hash: %s' % (H, H_check))
                    PASSED = False
                    exit(1)
                else:
                    log.info('Passed test `%s %s %s`.' % (pre, enc, post))
                #
                # Count the time.
                tf = clock()-ti
                SPEEDs[pre+' '+enc+' '+post] = tf
                SIZEs[pre+' '+enc+' '+post] = len(_enc)
                del _enc, _dec
                #
    #
    inv_SPEEDs = dict([[v,k] for k,v in SPEEDs.items()])
    inv_SIZEs = dict([[v,k] for k,v in SIZEs.items()])
    #
    log.info('''\n
    ----- ----- -----
    Statistics for test `%i`, size %s characters.
    Best speed is `%s` with %.3f sec.
    Smallest size is `%s` with %s characters.
    Worst speed is `%s` with %.3f sec.
    Largest size is `%s` with %s characters.
    ----- ----- -----\n''' % \
        ( f, splitthousands(L),
        inv_SPEEDs[min(SPEEDs.values())], min(SPEEDs.values()),
        inv_SIZEs[min(SIZEs.values())], splitthousands(min(SIZEs.values())),
        inv_SPEEDs[max(SPEEDs.values())], max(SPEEDs.values()),
        inv_SIZEs[max(SIZEs.values())], splitthousands(max(SIZEs.values())) ))
    #

if PASSED:
    log.info('Wheee! :) ALL TESTS PASSED!')
else:
    log.warning('NOT ALL TESTS PASSED! :(')

# Eof()
