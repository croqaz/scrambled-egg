
import os, shutil, glob
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
_ENCODE_D = {'Base64 Codec':'64', 'Base32 Codec':'32', 'HEX Codec':'H'}
PASSED = True

s = scrambled_egg.ScrambledEgg()

def RandPassword():
    # Returns a random password.
    L = random.randrange(3, 9)
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

log.basicConfig(level=10, format='%(asctime)s %(levelname)-10s %(message)s', datefmt='%y-%m-%d %H:%M:%S', filename='Testing2_Log.Log', filemode='w')
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
    # Create temp folder for images.
    try: os.mkdir(os.getcwd()+'/temp_test')
    except: pass
    #
    for pre in _SCRAMBLE_D:
        for enc in _ENC:
            for post in _ENCODE_D:
                #
                # IGNORE ROT13, it's not working with Binary files.
                if pre == 'ROT13': continue
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
                    log.error('Pwd: %s' % pwd)
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
    # Delete temp folder.
    try: shutil.rmtree(os.getcwd()+'/temp_test')
    except: pass
    #

if PASSED:
    log.info('Wheee! :) ALL TESTS PASSED!')
else:
    log.warning('NOT ALL TESTS PASSED! :(')

# Eof()
