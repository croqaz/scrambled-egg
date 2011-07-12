#!/usr/bin/env python

import os, shutil
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
_ENCODE_D = {'Base64 Codec':'64', 'Base32 Codec':'32', 'HEX Codec':'H'}

PASSED = True
TESTS = 10

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
    return ' '.join(txt)

def RandPassword():
    # Returns a random password between 1 and 128.
    L = random.randrange(1, 128)
    pwd = []
    for i in range(L):
        # From 'space' to '~'.
        pwd.append( chr(random.randrange(32, 126)) )
    pwd = ''.join(pwd)
    L = len(pwd)
    return pwd

def splitthousands(s, sep=','):
    # Splits large numbers with commas.
    s = str(s)
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

log.basicConfig(level=10, format='%(asctime)s %(levelname)-10s %(message)s', datefmt='%y-%m-%d %H:%M:%S', filename='Testing2_Log.Log', filemode='w')
console = log.StreamHandler() ; console.setLevel(10) ; log.getLogger('').addHandler(console) # Print + write log.
log.info('Preparing to run %i tests.\n' % TESTS)

for f in range(1, TESTS+1):
    #
    SPEEDs = {}
    SIZEs = {}
    log.info('Test number [%i] ...' % f)
    #
    txt = RandText()
    L = len(txt)
    H = MD5.new(txt).digest()
    #
    # Create temp folder for images.
    try: os.mkdir(os.getcwd()+'/temp_test')
    except: pass
    #
    for pre in _SCRAMBLE_D:
        for enc in _ENC:
            for post in _ENCODE_D:
                #
                ti = clock()
                img_path = os.getcwd()+'/temp_test/img_%s_%s_%s.png' % (pre, enc, post)
                #
                # Generate random password.
                pwd = RandPassword()
                #
                # Generate PNG Image.
                s.toImage(txt, pre, enc, post, pwd, img_path, True)
                #
                # Decrypt the image.
                _dec = s.fromImage(pwd, img_path, True)
                #
                if not _dec:
                    log.error('Error on test `%s %s %s`!' % (pre, enc, post))
                    log.debug('Pwd: %s' % pwd)
                    # An error will be raised on next line.
                #
                # Checking.
                if len(_dec) != L or MD5.new(_dec).digest() != H:
                    log.warning('Error! The result is not the same after encryption/ decryption with `%s %s %s`!' % (pre, enc, post))
                    PASSED = False
                else:
                    log.info('Passed test `%s %s %s`.' % (pre, enc, post))
                #
                # Count the time.
                tf = clock()-ti
                SPEEDs[pre+' '+enc+' '+post] = tf
                SIZEs[pre+' '+enc+' '+post] = len(open(img_path, 'rb').read())
                del _dec
                #
    #
    del txt
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
    # Delete temp folder.
    try: shutil.rmtree(os.getcwd()+'/temp_test')
    except: pass
    #

if PASSED:
    log.info('Wheee! :) ALL TESTS PASSED!')
else:
    log.warning('NOT ALL TESTS PASSED! :(')

# Eof()
