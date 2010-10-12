
import os, glob
import random
from time import clock
from Crypto.Hash import MD5
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
    # Returns a random password.
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

for f in files:
    #
    SPEEDs = {}
    SIZEs = {}
    fname = os.path.split(f)[1]
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
                # Encrypting.
                _enc = s.encrypt(txt, pre, enc, post, pwd, False)
                # Inserting random tag.
                tag = ['<#>%s:%s:%s<#>','[#]%s:%s:%s[#]','{#}%s:%s:%s{#}','(#)%s:%s:%s(#)'][random.randrange(0, 4)]
                tag = tag % (_SCRAMBLE_D[pre], _ENC[enc], _ENCODE_D[post].replace(' Codec',''))
                #
                # Put tag randomly at the beggining, or at the end, and
                # call decrypt without telling HOW to decrypt, the methods will be extracted from tags.
                if len(pwd) % 2:
                    _dec = s.decrypt(tag+_enc, None, None, None, pwd)
                else:
                    _dec = s.decrypt(_enc+tag, None, None, None, pwd)
                #
                if not _dec:
                    print('Decryption returned NULL!')
                    print(post, enc, pre, pwd, s.error)
                    # It will raise an error next line.
                #
                # Checking.
                if len(_dec) != L or MD5.new(_dec).digest() != H:
                    print('Error! The result is not the same after enc/ dec with "%s %s %s"!' % (post, enc, pre))
                    PASSED = False
                else:
                    print('Passed test "%s %s %s"!' % (pre, enc, post))
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
    print('----- ----- -----')
    print('Statistics for filename "%s", size "%s".' % ( fname, splitthousands(L) ))
    print('Best speed is %s "%.3f".' % ( inv_SPEEDs[min(SPEEDs.values())], min(SPEEDs.values()) ))
    print('Smallest size is %s "%s".' % ( inv_SIZEs[min(SIZEs.values())], splitthousands(min(SIZEs.values())) ))
    print('Worst speed is %s "%.3f", ' % ( inv_SPEEDs[max(SPEEDs.values())], max(SPEEDs.values()) ))
    print('Largest size is %s "%s".' % ( inv_SIZEs[max(SIZEs.values())], splitthousands(max(SIZEs.values())) ))
    print('----- ----- -----\n')
    #

if PASSED:
    print('ALL TESTS PASSED! :)')
else:
    print('NOT ALL TESTS PASSED! :(')

# Eof()
