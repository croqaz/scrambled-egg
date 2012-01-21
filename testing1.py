#!/usr/bin/env python

import os
from time import clock
from Crypto import Random
from Crypto.Random import random
from Crypto.Hash import MD5
import logging as log
import scrambled_egg

_SCRAMBLE_D = scrambled_egg.SCRAMBLE_D
del _SCRAMBLE_D['None']
_ENC = scrambled_egg.ENC
del _ENC['None']
_ENCODE_D = scrambled_egg.ENCODE_D

PASSED = True
TESTS = 3

s = scrambled_egg.ScrambledEgg()
s.rsa_path = 'k1.txt' # The path to the test RSA Key.

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
    L = random.randrange(1, 196)
    pwd = []
    for i in range(L):
        # From 'space' to '~'.
        pwd.append( chr(random.randrange(32, 126)).encode() )
    pwd = b''.join(pwd)
    L = len(pwd)
    return pwd

def splitthousands(s, sep=','):
    # Splits large numbers with commas.
    s = str(s)
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

log.basicConfig(level=10, format='%(asctime)s %(levelname)-10s %(message)s', datefmt='%y-%m-%d %H:%M:%S', filename='Testing1_Log.Log', filemode='w')
console = log.StreamHandler() ; console.setLevel(10) ; log.getLogger('').addHandler(console) # Print + write log.
log.info('Preparing to run %i tests.\n' % TESTS)

for f in range(1, TESTS+1):
    #
    SPEEDs = {}
    SIZEs = {}
    log.info('Test number [%i] ...' % f)
    #
    data = RandText()
    L = len(data)
    H = MD5.new(data).hexdigest()
    #
    for pre in _SCRAMBLE_D:
        for enc in _ENC:
            for post in _ENCODE_D:
                #
                # IGNORE Quopri, it's still UNSTABLE.
                if post == 'Quopri Codec': continue
                if enc == 'RSA': continue
                #
                ti = clock()
                #
                # Generate random password.
                pwd = RandPassword()
                #
                # Encrypting without adding tags.
                if len(pwd) % 2:
                    _enc = s.encrypt(data, pre, enc, post, pwd, False)
                    _dec = s.decrypt(_enc.encode(), post, enc, pre, pwd)
                else:
                    _enc = s.encrypt(data, pre, enc, post, pwd)
                    _dec = s.decrypt(_enc.encode(), None, None, None, pwd)
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
    del data
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
