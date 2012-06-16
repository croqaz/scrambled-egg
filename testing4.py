
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
        # _encrults list
        _encrults = []
        #
        for pre in _SCRAMBLE_D:
            for enc in _ENC:
                for post in _ENCODE_D:

                    encr_result = False
                    decr_result = False
                    self.frame.leftText.Clear()
                    self.frame.linePasswordL.Clear()
                    self.frame.onCryptMode(None)

                    # IGNORE Quopri, it's UNSTABLE.
                    if post == 'Quopri Codec': continue
                    if enc == 'RSA': continue

                    txt = RandText()
                    pwd = RandPassword()
                    tags = len(pwd) % 2

                    # BEGIN ENCRYPTION
                    if tags:
                        self.frame.setTags.SetValue(True)
                        _encr = self.SE.encrypt(txt, pre, enc, post, pwd, True)
                        _decr = self.SE.decrypt(_encr, None, None, None, pwd)
                    else:
                        self.frame.setTags.SetValue(False)
                        _encr = self.SE.encrypt(txt, pre, enc, post, pwd, False)
                        _decr = self.SE.decrypt(_encr, post, enc, pre, pwd)
                    #
                    self.frame.preProcess.SetValue(pre)
                    self.frame.comboCrypt.SetValue(enc)
                    self.frame.postProcess.SetValue(post)
                    self.frame.linePasswordL.SetValue(pwd)
                    self.frame.leftText.SetValue(txt)
                    #
                    gui_encr = self.frame.rightText.GetValue()
                    encr_result = (_encr == gui_encr)
                    time.sleep(0.1)

                    # BEGIN DECRYPTION
                    self.frame.rightText.Clear()
                    self.frame.linePasswordR.Clear()
                    self.frame.preDecrypt.SetValue(pre)
                    self.frame.comboDecrypt.SetValue(enc)
                    self.frame.postDecrypt.SetValue(post)
                    self.frame.onDecryptMode(None)
                    self.frame.linePasswordR.SetValue(pwd)
                    self.frame.rightText.SetValue(_encr)
                    #
                    gui_decr = self.frame.leftText.GetValue()
                    decr_result = (_decr == gui_decr)
                    time.sleep(0.1)
                    #
                    self.frame.Update()

                    if encr_result and decr_result:
                        print 'PASSED test `%s %s %s %s`. Pwd len=%i, Txt len=%i.' % \
                            (pre, enc, post, tags, len(pwd), len(txt))
                    else:
                        print 'FAILED test `{pre} {enc} {post} {tags}`! Pwd len={len_pwd}, Txt len={len_txt}.\n' \
                            'SE encr={len_encr} , GUI encr={len_gencr} ; SE decr={len_decr} , GUI decr={len_dencr}'.format(
                                pre=pre, enc=enc, post=post, tags=tags, len_pwd=len(pwd), len_txt=len(txt),
                                len_encr=len(_encr), len_gencr=len(gui_encr),
                                len_decr=len(_decr), len_dencr=len(gui_decr),)
                    #
                    _encrults.append(encr_result and decr_result)
                    #
        #
        self.assertEqual(len(_encrults), sum(_encrults))
        #

#

if __name__ == '__main__':
    unittest.main()
