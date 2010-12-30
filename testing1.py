
import os, glob
import random
from time import clock
from Crypto.Hash import MD5
import logging as log
import scrambled_egg

path = '/media/Data/Projects/p-scrambled-egg/trunk/some_files'
#path = r'd:\Projects\p-scrambled-egg\trunk\some_files'
files = glob.glob(path+'/*.*')

_SCRAMBLE_D = scrambled_egg.SCRAMBLE_D
del _SCRAMBLE_D['None']
_ENC = scrambled_egg.ENC
del _ENC['None']
_ENCODE_D = scrambled_egg.ENCODE_D
PASSED = True

s = scrambled_egg.ScrambledEgg()

def RandPassword():
    # Returns a random password between 3 and 99.
    L = random.randrange(3, 99)
    pwd = []
    for i in range(L):
        pwd.append( chr(random.randrange(48, 122)) )
    pwd = ''.join(pwd)
    L = len(pwd)
    return pwd

def splitthousands(s, sep=','):
    # Splits large numbers with commas.
    s = str(s)
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

log.basicConfig(level=10, format='%(asctime)s %(levelname)-10s %(message)s', datefmt='%y-%m-%d %H:%M:%S', filename='Testing1_Log.Log', filemode='w')
console = log.StreamHandler() ; console.setLevel(10) ; log.getLogger('').addHandler(console) # Print + write log.
log.info('Testing started, %i files.\n' % len(files))

for f in files:
    #
    SPEEDs = {}
    SIZEs = {}
    fname = os.path.split(f)[1]
    log.info('Testing filename `%s`.' % fname)
    #
    txt = open(f, 'rb').read()
    L = len(txt)
    H = MD5.new(txt).digest()
    #
    for pre in _SCRAMBLE_D:
        for enc in _ENC:
            for post in _ENCODE_D:
                #
                # IGNORE Quopri, it's still UNSTABLE.
                if post == 'Quopri Codec': continue
                #
                ti = clock()
                # Generate random password.
                pwd = RandPassword()
                # Encrypting without adding tags.
                _enc = s.encrypt(txt, pre, enc, post, pwd, False)
                # Inserting random tag.
                tag = ['<#>%s:%s:%s<#>','[#]%s:%s:%s[#]','{#}%s:%s:%s{#}','(#)%s:%s:%s(#)'][random.randrange(0, 4)]
                tag = tag % (_SCRAMBLE_D[pre], _ENC[enc], _ENCODE_D[post].replace(' Codec',''))
                #
                # Put tag randomly at the beggining, or at the end, and
                # call decrypt without telling Scrambled-Egg HOW to decrypt,
                # the methods will be extracted from tags.
                if len(pwd) % 2:
                    _dec = s.decrypt(tag+_enc, None, None, None, pwd)
                else:
                    _dec = s.decrypt(_enc+tag, None, None, None, pwd)
                #
                if not _dec:
                    log.error('Error on test `%s %s %s`!' % (pre, enc, post))
                    log.debug('Pwd: %s ; Tag: %s' % (pwd, tag))
                    log.debug(s.error.strip())
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
                SIZEs[pre+' '+enc+' '+post] = len(_enc)
                del _enc, _dec
                #
    #
    del txt
    inv_SPEEDs = dict([[v,k] for k,v in SPEEDs.items()])
    inv_SIZEs = dict([[v,k] for k,v in SIZEs.items()])
    #
    log.info('''\n
    ----- ----- -----
    Statistics for filename `%s`, size %s bytes.
    Best speed is `%s` with %.3f sec.
    Smallest size is `%s` with %s bytes.
    Worst speed is `%s` with %.3f sec.
    Largest size is `%s` with %s bytes.
    ----- ----- -----\n''' % \
        ( fname, splitthousands(L),
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
