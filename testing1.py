
import os, glob
import random
from time import clock
import scrambled_egg

path = '/media/Data/DataBase'
#path = r'd:\Pictures\Ficr'

files = glob.glob(path+'/*.*t*')
try: os.mkdir(path+'/segg_test')
except: pass

SCRAMBLE_D = scrambled_egg.SCRAMBLE_D
del SCRAMBLE_D['None']
ENC = scrambled_egg.ENC
del ENC['None']
ENCODE_D = scrambled_egg.ENCODE_D
TEST_PASSED = True

s = scrambled_egg.ScrambledEgg()

def RandPassword(enc):
    # Returns a random password.
    L = random.randrange(3, 99)
    pwd = []
    #
    for i in range(L):
        pwd.append( chr(random.randrange(48, 122)) )
    pwd = ''.join(pwd)
    L = len(pwd)
    #
    #print pwd + ' -> ' + str(len(pwd))
    return pwd
    #

def splitthousands(s, sep=','):
    s = str(s)
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

for f in files:
    #
    SPEEDs = {}
    SIZEs = {}
    fname = os.path.split(f)[1]
    #
    for pre in SCRAMBLE_D:
        for enc in ENC:
            for post in ENCODE_D:
                ti = clock()
                final = s.encrypt(open(f, 'rb').read(), pre, enc, post, RandPassword(enc))
                g = open('%s/segg_test/%s_%s_%s_%s.segg' % (path, pre, enc, post, fname), 'wb')
                g.write(final)
                g.close()
                tf = clock()-ti
                SPEEDs[pre+' '+enc+' '+post] = tf
                SIZEs[pre+' '+enc+' '+post] = os.path.getsize(g.name)
                del g
    #
    inv_SPEEDs = dict([[v,k] for k,v in SPEEDs.items()])
    inv_SIZEs = dict([[v,k] for k,v in SIZEs.items()])
    print('----- ----- -----')
    print('Statistics for filename "%s", size "%s".' % ( fname, splitthousands(os.path.getsize(f)) ))
    print('Best speed is %s "%.3f".' % ( inv_SPEEDs[min(SPEEDs.values())], min(SPEEDs.values()) ))
    print('Smallest size is %s "%s".' % ( inv_SIZEs[min(SIZEs.values())], splitthousands(min(SIZEs.values())) ))
    print('Worst speed is %s "%.3f", ' % ( inv_SPEEDs[max(SPEEDs.values())], max(SPEEDs.values()) ))
    print('Largest size is %s "%s".' % ( inv_SIZEs[max(SIZEs.values())], splitthousands(max(SIZEs.values())) ))
    print('----- ----- -----\n')
    #

# Eof()
