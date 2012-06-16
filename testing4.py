
import wx
import time
import unittest
import binascii as ba
from Crypto import Random
from Crypto.Random import random

import scrambled_egg
import scrambled_gui

_SCRAMBLE_D = scrambled_egg.SCRAMBLE_D
del _SCRAMBLE_D['None']
_ENC = scrambled_egg.ENC
del _ENC['None']
_ENCODE_D = scrambled_egg.ENCODE_D

#

def RandText():
    # Returns a random piece of text.
    words = random.randrange(1, 99)
    txt = []
    for i in range(words):
        # Word length.
        L = random.randrange(1, 99)
        txt.append(Random.new().read(L))
    return ba.b2a_base64(' '.join(txt))

def RandPassword():
    # Returns a random password between 1 and 196.
    L = random.randrange(1, 196)
    pwd = []
    for i in range(L):
        # From 'space' to '~'.
        pwd.append( chr(random.randrange(32, 126)).encode() )
    pwd = ''.join(pwd)
    L = len(pwd)
    return pwd

#

class TestGui(unittest.TestCase):

    def setUp(self):
        self.app = wx.App()
        self.frame = scrambled_gui.Window()
        self.SE = scrambled_egg.ScrambledEgg()

    def tearDown(self):
        self.frame.Destroy()

    def testEncr(self):
        #
        # Results list
        results = []
        #
        for pre in _SCRAMBLE_D:
            for enc in _ENC:
                for post in _ENCODE_D:
                    #
                    self.frame.leftText.Clear()
                    self.frame.linePasswordL.Clear()
                    #
                    # IGNORE Quopri, it's still UNSTABLE.
                    if post == 'Quopri Codec': continue
                    if enc == 'RSA': continue
                    #
                    txt = RandText()
                    pwd = RandPassword()
                    #
                    if len(pwd) % 2:
                        print 'No tags',
                        self.frame.setTags.SetValue(True)
                        res = self.SE.encrypt(txt, pre, enc, post, pwd, False)
                    else:
                        print 'With tags',
                        self.frame.setTags.SetValue(False)
                        res = self.SE.encrypt(txt, pre, enc, post, pwd, True)
                    #
                    self.frame.preProcess.SetValue(pre)
                    self.frame.comboCrypt.SetValue(enc)
                    self.frame.postProcess.SetValue(post)
                    self.frame.linePasswordL.SetValue(pwd)
                    self.frame.leftText.SetValue(txt)
                    #
                    gui_res = self.frame.rightText.GetValue()
                    self.frame.Update()
                    #
                    print 'Test `%s %s %s` -> %s. Pwd len=%i, Txt len=%i.' % \
                        (pre, enc, post, res==gui_res, len(pwd), len(txt))
                    results.append(res == gui_res)
                    #
                    time.sleep(0.1)
                    #
        #
        self.assertEqual(len(results), sum(results))
        #

#

if __name__ == '__main__':
    unittest.main()
