#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.blogspot.com.
# ---

import os, sys
import re, math
import string
import base64
import binascii as ba
import hashlib
import bz2, zlib

from Crypto.Cipher import AES
from Crypto.Cipher import ARC2
from Crypto.Cipher import CAST
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES3

import sip
sip.setapi('QString', 2)
sip.setapi('QVariant', 2)

from PyQt4 import QtCore
from PyQt4 import QtGui


#
ROT = string.maketrans('nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
#
SCRAMBLE = ['None', 'ROT13', 'ZLIB', 'BZ2']
SCRAMBLE_D = {'None':'N', 'ROT13':'R', 'ZLIB':'ZL', 'BZ2':'BZ'}
ENC = {'AES':'AE', 'ARC2':'AR', 'CAST':'CA', 'Blowfish':'B', 'DES3':'D', 'None':'N'}
ENCODE = ['Base64 Codec', 'Base32 Codec', 'HEX Codec', 'Quopri Codec', 'String Escape', 'UU Codec', 'XML']
ENCODE_D = {'Base64 Codec':'64', 'Base32 Codec':'32', 'HEX Codec':'H', 'Quopri Codec':'Q', 'String Escape':'STR', 'UU Codec':'UU', 'XML':'XML'}
NO_TAGS = re.compile(
    '<#>(?P<ts>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})</?#>|' \
    '\[#\](?P<tq>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\[#\]|' \
    '\{#\}(?P<ta>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\{#\}|' \
    '\(#\)(?P<tp>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\(#\)')
# These numbers are used when creating PNG images.
SCRAMBLE_NR = {'None':'1', 'ROT13':'2', 'ZLIB':'3', 'BZ2':'4'}
ENCRYPT_NR = {'AES':'1', 'ARC2':'2', 'CAST':'3', 'Blowfish':'5', 'DES3':'4', 'None':'9'}
ENCODE_NR = {'Base64 Codec':'4', 'Base32 Codec':'2', 'HEX Codec':'1', 'Quopri Codec':'9', 'String Escape':'6', 'UU Codec':'8', 'XML':'7'}
#


class ScrambledEgg():

    def __init__(self):
        self.error = ''

    def __error(self, step, pre, enc, post, field='R'):
        #
        if step==1:
            if field=='R':
                pre += ' (ERROR!)'
            else:
                pre += ' (IGNORED!)'
        elif step==2:
            enc += ' (ERROR!)'
        elif step==3:
            post += ' (ERROR!)'
        #
        if field=='R':
            self.error = '  Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post)
        else:
            self.error = '  Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post)
        #

    def _fix_password(self, pwd, enc):
        #
        L = len(pwd)
        #
        if enc == 'AES' or enc == ENC['AES']:
            # MAXIMUM 32 characters for AES !
            if L == 32:
                pass
            elif L > 32:
                pwd = hashlib.sha256(pwd).digest()
            else:
                pwd += 'X' * ( (((L/16)+1)*16) - L )
        if enc == 'CAST' or enc == ENC['CAST']:
            # MAXIMUM 8 characters for CAST !
            if L == 8:
                pass
            elif L > 8:
                pwd = hashlib.md5(pwd).digest()
            else:
                pwd += 'X' * ( (((L/8)+1)*8) - L )
        if enc == 'Blowfish' or enc == ENC['Blowfish']:
            # MAXIMUM 56 characters for Blowfish !
            if L == 56:
                pass
            elif L > 56:
                pwd = hashlib.sha224(pwd).hexdigest()
            else:
                pwd += 'X' * ( (((L/8)+1)*8) - L )
        if enc == 'DES3' or enc == ENC['DES3']:
            # MAXIMUM 24 characters for DES3 !
            if L == 24:
                pass
            elif L > 24:
                pwd = 'XX' + hashlib.sha1(pwd).digest() + 'XX'
            else:
                pwd += 'X' * ( (((L/24)+1)*24) - L )
        elif not pwd:
            # Only for NULL passwords.
            pwd = 'X'
        #
        return pwd
        #

    def encrypt(self, txt, pre, enc, post, pwd, tags=True):
        #
        # Scramble operation.
        if pre == 'None':
            pass
        elif pre == 'ZLIB':
            txt = zlib.compress(txt)
        elif pre == 'BZ2':
            txt = bz2.compress(txt)
        elif pre == 'ROT13':
            txt = string.translate(txt, ROT)
        else:
            raise Exception('Invalid scramble "%s" !' % pre)
        #
        pwd = self._fix_password(pwd, enc)
        L = len(txt)
        txt += ' ' * ( (((L/16)+1)*16) - L )
        #
        # Encryption operation.
        if enc == 'AES':
            o = AES.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'ARC2':
            o = ARC2.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'CAST':
            o = CAST.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'Blowfish':
            o = Blowfish.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'DES3':
            o = DES3.new(pwd, mode=2)
            encrypted = o.encrypt(txt)
        elif enc == 'None':
            encrypted = txt
        else:
            raise Exception('Invalid encryption mode "%s" !' % enc)
        #
        # Codec operation.
        if post == 'Base64 Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_base64(encrypted))
            else:
                final = ba.b2a_base64(encrypted)
        elif post == 'Base32 Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), base64.b32encode(encrypted))
            else:
                final = base64.b32encode(encrypted)
        elif post == 'HEX Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_hex(encrypted))
            else:
                final = ba.b2a_hex(encrypted)
        elif post == 'Quopri Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_qp(encrypted, quotetabs=True, header=True))
            else:
                final = ba.b2a_qp(encrypted, quotetabs=True, header=True)
        elif post == 'String Escape':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], encrypted.encode('string_escape'))
            else:
                final = encrypted.encode('string_escape')
        elif post == 'UU Codec':
            if tags:
                final = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), encrypted.encode('uu'))
            else:
                final = encrypted.encode('uu')
        elif post == 'XML':
            if tags:
                final = '<root>\n<#>%s:%s:%s</#>\n<data>%s</data>\n</root>' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], ba.b2a_base64(encrypted))
            else:
                final = '<root>\n<data>%s</data>\n</root>' % ba.b2a_base64(encrypted)
        else:
            raise Exception('Invalid codec "%s" !' % post)
        #
        return final
        #

    def decrypt(self, txt, pre, enc, post, pwd):
        #
        # Trying to identify and/or delete `meta-tags`.
        try:
            re_groups = re.search(NO_TAGS, txt).groups()
            info = re_groups[0] or re_groups[1] or re_groups[2] or re_groups[3]
            txt = re.sub(NO_TAGS, '', txt)
            # Identify here.
            if not pre:
                pre = info.split(':')[2]
            if not enc:
                enc = info.split(':')[1]
            if not post:
                post = info.split(':')[0]
        except:
            pass
        #
        # Adapting password for encryption.
        pwd = self._fix_password(pwd, enc)
        #
        # Codec operation.
        if not pre:
            self.__error(1, 'None', enc, post) ; return
        elif pre == 'Base64 Codec' or pre == ENCODE_D['Base64 Codec']:
            try: txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Base32 Codec' or pre == ENCODE_D['Base32 Codec']:
            try: txt = base64.b32decode(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'HEX Codec' or pre == ENCODE_D['HEX Codec']:
            try: txt = ba.a2b_hex(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Quopri Codec' or pre == ENCODE_D['Quopri Codec']:
            try: txt = ba.a2b_qp(q_txt, header=True)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'String Escape'  or pre == ENCODE_D['String Escape']:
            try: txt = txt.decode('string_escape')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'UU Codec'  or pre == ENCODE_D['UU Codec']:
            try: txt = txt.decode('uu')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'XML':
            try:
                txt = txt.replace('\n', '')
                txt = txt.replace('<root>', '')
                txt = txt.replace('</root>', '')
                txt = txt.replace('<data>', '')
                txt = txt.replace('</data>', '')
                txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        else:
            raise Exception('Invalid codec "%s" !' % pre)
        #
        # Decryption operation.
        if enc == 'AES' or enc == ENC['AES']:
            o = AES.new(pwd, mode=2)
        elif enc == 'ARC2' or enc == ENC['ARC2']:
            o = ARC2.new(pwd, mode=2)
        elif enc == 'CAST' or enc == ENC['CAST']:
            o = CAST.new(pwd, mode=2)
        elif enc == 'Blowfish' or enc == ENC['Blowfish']:
            o = Blowfish.new(pwd, mode=2)
        elif enc == 'DES3' or enc == ENC['DES3']:
            o = DES3.new(pwd, mode=2)
        elif not enc or enc == 'None':
            txt = txt.rstrip(' ')
        else:
            raise Exception('Invalid decrypt "%s" !' % enc)
        #
        if enc != 'None':
            try: txt = o.decrypt(txt).rstrip(' ')
            except: self.__error(2, pre, enc, post) ; return
        #
        # Un-scramble operation.
        if not post or post == 'None':
            final = txt
        elif post == 'ZLIB' or post == SCRAMBLE_D['ZLIB']:
            try: final = zlib.decompress(txt)
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'BZ2' or post == SCRAMBLE_D['BZ2']:
            try: final = bz2.decompress(txt)
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'ROT13' or post == SCRAMBLE_D['ROT13']:
            final = string.translate(txt, ROT)
        else:
            raise Exception('Invalid scramble "%s" !' % post)
        #
        return final
        #

    def toImage(self, txt, pre, enc, post, pwd, path, encrypt=True):
        '''
        Any information, text and/or files, can be encoded inside a little PNG image.
        Depending on how you encode the crypted data, images come in 3 flavors: HEX, Base32 and Base64.
        Each letter is transformed into a color from 1 to 255. Four colors become one pixel.
        HEX encoding is `high density`. One pixel is made of 8 letters, instead of 4 letters.
        '''
        #
        # Input can be string, or file. If is file, read it.
        if str(type(txt)) == "<type 'file'>":
            txt.seek(0)
            txt = txt.read()

        # Pre/ Enc/ Post information.
        if post == 'HEX Codec':
            first_pixel = '2'
        else:
            first_pixel = '1'
        first_pixel += SCRAMBLE_NR[pre] + ENCRYPT_NR[enc] + ENCODE_NR[post]
        
        if encrypt: # If text MUST be encrypted first.
            val = self.encrypt(txt, pre, enc, post, pwd)[::-1]
            if not val:
                return
        else: # Else, the text is already encrypted.
            val = txt[::-1]
        # Add Pre/ Enc/ Post information.
        val += first_pixel
        del first_pixel

        # Calculate the edge of the square and blank square.
        if post == 'HEX Codec':
            edge = math.ceil(math.sqrt( float(len(val))/8.0 ))
            blank = math.ceil((edge * edge - float(len(val))/8.0) / 2.0)
        else:
            edge = math.ceil(math.sqrt( float(len(val))/4.0 ))
            blank = math.ceil((edge * edge - float(len(val))/4.0) / 2.0)

        # Explode the encrypted string.
        list_val = list(val)
        # New square image.
        print('Creating new image, %ix%i, blank is %i, string to encode is %i characters.' % (edge, edge, blank, len(val)))
        im = QtGui.QImage(edge, edge, QtGui.QImage.Format_ARGB32)
        _pix = im.setPixel
        _rgba = QtGui.qRgba
        _int = int
        _ord = ord

        # HEX is `high density`.
        if post == 'HEX Codec':
            for i in range(int(edge)):
                for j in range(int(edge)):
                    #
                    _r = _g = _b = _a = 255
                    #
                    # Red
                    if len(list_val) >= 2:
                        _r = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _r = _int(list_val.pop(), 16)
                    #
                    # Green
                    if len(list_val) >= 2:
                        _g = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _g = _int(list_val.pop(), 16)
                    #
                    # Blue
                    if len(list_val) >= 2:
                        _b = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _b = _int(list_val.pop(), 16)
                    #
                    # Alpha
                    if len(list_val) >= 2:
                        _a = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _a = __int(list_val.pop(), 16)
                    #
                    _pix(j, i, _rgba(_r, _g, _b, _a))
                    #

        # Base 64 and Base 32.
        else:
            for i in range(int(edge)):
                for j in range(int(edge)):
                    #
                    if blank:
                        blank -= 1
                        _pix(j, i, _rgba(255, 255, 255, 255))
                        continue
                    #
                    _r = _g = _b = _a = 255
                    #
                    if len(list_val) >= 1:
                        _r = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _g = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _b = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _a = _ord(list_val.pop())
                    #
                    _pix(j, i, _rgba(_r, _g, _b, _a))
                    #

        #
        try:
            im.save(path, 'PNG', -1)
        except:
            print('Cannot save PNG file "%s" !' % path)
        #

    def fromImage(self, pre, enc, post, pwd, path, decrypt=True):
        #
        if not os.path.isfile(path):
            print('Cannot find file "%s" !' % path)
            return
        #
        try:
            im = QtGui.QImage()
            im.load(path, 'PNG')
        except:
            print('Image "%s" is not a valid RGBA PNG !' % path)
            return
        #
        list_val = []
        _pix = im.pixel
        _r = QtGui.qRed
        _g = QtGui.qGreen
        _b = QtGui.qBlue
        _a = QtGui.qAlpha
        #
        first_pixel = 0
        # Calculate first pixel.
        for i in range(im.width()):
            for j in range(im.height()):
                #
                rgba0 = _pix(j, i)
                # If it's not a blank pixel.
                if rgba0 != 4294967295L:
                    first_pixel = [_r(rgba0), _g(rgba0), _b(rgba0), _a(rgba0)]
                    break
                #
            if first_pixel:
                break

        # Reverse number dictionaries.
        reverse_s = dict(zip(SCRAMBLE_NR.values(), SCRAMBLE_NR.keys()))
        reverse_ey = dict(zip(ENCRYPT_NR.values(), ENCRYPT_NR.keys()))
        reverse_ed = dict(zip(ENCODE_NR.values(), ENCODE_NR.keys()))

        # If not HD.
        if first_pixel[3] == 49:
            pre = reverse_ed[unichr(first_pixel[0])]
            enc = reverse_ey[unichr(first_pixel[1])]
            post = reverse_s[unichr(first_pixel[2])]

        # If HD.
        elif first_pixel[1] == 18 or first_pixel[1] == 34 or first_pixel[1] == 50 or first_pixel[1] == 66:
            pixel = hex(int(first_pixel[0]))[-2:] + hex(int(first_pixel[1]))[-2:]
            pre = reverse_ed[pixel[0]]
            enc = reverse_ey[pixel[1]]
            post = reverse_s[pixel[2]]

        # For HEX.
        if pre == 'HEX Codec':
            for i in range(im.width()):
                for j in range(im.height()):
                    #
                    rgba = _pix(j, i)
                    #
                    # For each channel in this pixel.
                    for v in [_r(rgba), _g(rgba), _b(rgba), _a(rgba)]:
                        if v < 16:
                            list_val.append('0'+hex(v)[-1:])
                        else:
                            list_val.append(hex(v)[-2:])
                    #

        # For the rest.
        else:
            for i in range(im.width()):
                for j in range(im.height()):
                    #
                    rgba = _pix(j, i)
                    #
                    for v in [_r(rgba), _g(rgba), _b(rgba), _a(rgba)]:
                        if v and v != 255:
                            list_val.append(unichr(v))
                        # If this color is 0 or 255, the rest of the pixel is blank.
                        else:
                            break
                    #

        # If the text MUST be decrypted.
        if decrypt:
            val = self.decrypt(''.join(list_val), pre, enc, post, pwd)
            if not val:
                print(self.error)
            else:
                return val[4:]

        # Else, don't decrypt.
        else:
            val = ''.join(list_val)
            return val[4:]
        #

    def _import(self, pre, enc, post, pwd, fpath, decrypt=True):
        #
        if not os.path.isfile(fpath):
            print('Cannot find file "%s" !' % fpath)
            return
        #
        ext = os.path.splitext(fpath)[1].lower()
        #
        # For PNG files.
        if ext=='.png':
            return self.fromImage(pre, enc, post, pwd, fpath, decrypt)
        #
        # For the rest of the files.
        if decrypt:
            val = self.decrypt(open(fpath, 'rb').read(), pre, enc, post, pwd)
            if not val:
                print(self.error)
            else:
                return val
        # Else, don't decrypt.
        else:
            val = open(fpath, 'rb').read()
            return val
        #

class Window(QtGui.QMainWindow):

    def __init__(self):
        '''
        Init function.
        '''
        super(Window, self).__init__()
        self.resize(800, 400)
        self.setWindowTitle('Scrambled Egg :: Live Crypt')
        QtGui.QApplication.setStyle(QtGui.QStyleFactory.create('CleanLooks'))
        QtGui.QApplication.setPalette(QtGui.QApplication.style().standardPalette())
        self.SE = ScrambledEgg()

        self.centralWidget = QtGui.QWidget(self) # Central Widget.
        self.setCentralWidget(self.centralWidget)

        self.statusBar = QtGui.QStatusBar(self)  # Status Bar.
        self.setStatusBar(self.statusBar)
        self.layout = QtGui.QGridLayout(self.centralWidget) # Main Layout.
        self.centralWidget.setLayout(self.layout)

        self.leftText = QtGui.QTextEdit(self.centralWidget)       # To write clean text.
        self.rightText = QtGui.QPlainTextEdit(self.centralWidget) # To view encrypted text.

        self.buttonCryptMode = QtGui.QPushButton('Encrypt Mode', self.centralWidget)
        self.buttonDecryptMode = QtGui.QPushButton('Decrypt Mode', self.centralWidget)

        self.preProcess = QtGui.QComboBox(self.centralWidget)  # Left side.
        self.comboCrypt = QtGui.QComboBox(self.centralWidget)  # Left side.
        self.postProcess = QtGui.QComboBox(self.centralWidget) # Left side.
        self.linePasswordL = QtGui.QLineEdit(self.centralWidget) # Left side.
        self.checkPwdL = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Left side.
        self.nrLettersL = QtGui.QLabel('', self.centralWidget) # Left side.
        self.setFormatting = QtGui.QCheckBox('Formatted text', self.centralWidget) # Left side.
        self.setTags = QtGui.QCheckBox('No tags', self.centralWidget) # Left side.

        self.preDecrypt = QtGui.QComboBox(self.centralWidget)    # Right side.
        self.comboDecrypt = QtGui.QComboBox(self.centralWidget)  # Right side.
        self.postDecrypt = QtGui.QComboBox(self.centralWidget)   # Right side.
        self.linePasswordR = QtGui.QLineEdit(self.centralWidget) # Right side.
        self.checkPwdR = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Right side.
        self.nrLettersR = QtGui.QLabel('', self.centralWidget) # Right side.
        self.loadFile = QtGui.QPushButton('Import', self.centralWidget) # Right side.
        self.saveFile = QtGui.QPushButton('Export', self.centralWidget) # Left side.

        self.layout.addWidget(self.buttonCryptMode, 1, 1, 1, 5)
        self.layout.addWidget(self.buttonDecryptMode, 1, 6, 1, 5)

        self.layout.addWidget(self.preProcess, 2, 1, 1, 1)
        self.layout.addWidget(self.comboCrypt, 2, 2, 1, 1)
        self.layout.addWidget(self.postProcess, 2, 3, 1, 1)
        self.layout.addWidget(self.preDecrypt, 2, 6, 1, 1)
        self.layout.addWidget(self.comboDecrypt, 2, 7, 1, 1)
        self.layout.addWidget(self.postDecrypt, 2, 8, 1, 1)
        self.layout.addWidget(self.setFormatting, 21, 1, 1, 1)
        self.layout.addWidget(self.setTags, 21, 2, 1, 1)

        self.layout.addWidget(self.loadFile, 21, 6, 1, 1)
        self.layout.addWidget(self.saveFile, 21, 7, 1, 1)

        self.layout.addWidget(self.linePasswordL, 3, 1, 1, 4)
        self.layout.addWidget(self.checkPwdL, 3, 5, 1, 1)
        self.layout.addWidget(self.linePasswordR, 3, 6, 1, 4)
        self.layout.addWidget(self.checkPwdR, 3, 10, 1, 1)

        self.layout.addWidget(self.nrLettersL, 21, 5, 1, 1)
        self.layout.addWidget(self.nrLettersR, 21, 10, 1, 1)
        self.layout.addWidget(self.leftText, 5, 1, 10, 5)
        self.layout.addWidget(self.rightText, 5, 6, 10, 5)

        self.__setup() # Prepair all components!
        self.__connect() # Connect all components!

    def __setup(self):
        '''
        Setup all components.
        '''
        #
        # Toogle buttons.
        self.buttonCryptMode.setCheckable(True)
        self.buttonCryptMode.setChecked(True)
        self.buttonCryptMode.setToolTip('Switch to Encryption mode')
        self.buttonDecryptMode.setCheckable(True)
        self.buttonDecryptMode.setToolTip('Switch to Decryption mode')
        #
        # Password fields.
        self.linePasswordL.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordL.setToolTip('Password used for encrypting the text')
        self.linePasswordL.setMaxLength(99)
        self.checkPwdL.setTristate(False)
        self.linePasswordR.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordR.setToolTip('Password used for decrypting the text')
        self.linePasswordR.setMaxLength(99)
        self.linePasswordR.setDisabled(True)
        self.checkPwdR.setTristate(False)
        #
        # Formatted text.
        self.setFormatting.setTristate(False)
        self.setTags.setTristate(False)
        #
        MIN = 120
        self.preProcess.setMinimumWidth(MIN)
        self.comboCrypt.setMinimumWidth(MIN)
        self.postProcess.setMinimumWidth(MIN)
        self.preDecrypt.setMinimumWidth(MIN)
        self.comboDecrypt.setMinimumWidth(MIN)
        self.postDecrypt.setMinimumWidth(MIN)
        #
        # Pre combo-boxes.
        self.preProcess.setToolTip('Select pre-process')
        self.postDecrypt.setToolTip('Select post-decrypt')
        for scramble in SCRAMBLE:
            self.preProcess.addItem(scramble, scramble)
            self.postDecrypt.addItem(scramble, scramble)
        #
        # Encryption/ decryption combo-boxes.
        self.comboCrypt.setToolTip('Select encryption algorithm; it will use the provided password')
        self.comboDecrypt.setToolTip('Select encryption algorithm; it will use the provided password')
        for enc in sorted(ENC.keys()):
            self.comboCrypt.addItem(enc, enc)
            self.comboDecrypt.addItem(enc, enc)
        #
        # Post combo-boxes.
        self.postProcess.setToolTip('Select post-process')
        self.preDecrypt.setToolTip('Select pre-decrypt')
        for encode in ENCODE:
            self.postProcess.addItem(encode, encode)
            self.preDecrypt.addItem(encode, encode)
        #

    def __connect(self):
        '''
        Connect all components.
        '''
        #
        self.linePasswordL.textChanged.connect(self.onLeftTextChanged)
        self.leftText.textChanged.connect(self.onLeftTextChanged)
        self.checkPwdL.stateChanged.connect(self.onCryptMode)
        self.buttonCryptMode.clicked.connect(self.onCryptMode)
        #
        self.linePasswordR.textChanged.connect(self.onRightTextChanged)
        self.rightText.textChanged.connect(self.onRightTextChanged)
        self.checkPwdR.stateChanged.connect(self.onDecryptMode)
        self.buttonDecryptMode.clicked.connect(self.onDecryptMode)
        #
        self.preProcess.currentIndexChanged.connect(self.onLeftTextChanged)
        self.comboCrypt.currentIndexChanged.connect(self.onLeftTextChanged)
        self.postProcess.currentIndexChanged.connect(self.onLeftTextChanged)
        #
        self.preDecrypt.currentIndexChanged.connect(self.onRightTextChanged)
        self.comboDecrypt.currentIndexChanged.connect(self.onRightTextChanged)
        self.postDecrypt.currentIndexChanged.connect(self.onRightTextChanged)
        #
        self.saveFile.clicked.connect(self.onSave)
        self.loadFile.clicked.connect(self.onLoad)
        self.setFormatting.toggled.connect(self.onLeftTextChanged)
        self.setTags.toggled.connect(self.onLeftTextChanged)
        #
        # ACTION !
        self.onCryptMode()
        #

    def onCryptMode(self):
        #
        self.buttonCryptMode.setChecked(True)
        self.buttonDecryptMode.setChecked(False)
        #
        self.linePasswordL.setDisabled(False)
        self.leftText.setReadOnly(False)
        self.linePasswordR.setDisabled(True)
        self.rightText.setReadOnly(True)
        #
        self.checkPwdL.setDisabled(False)
        self.checkPwdR.setDisabled(True)
        #
        if self.checkPwdL.isChecked():
            self.linePasswordL.setEchoMode(QtGui.QLineEdit.Normal)
        else:
            self.linePasswordL.setEchoMode(QtGui.QLineEdit.Password)
        #
        self.preProcess.setCurrentIndex(self.postDecrypt.currentIndex())
        self.comboCrypt.setCurrentIndex(self.comboDecrypt.currentIndex())
        self.postProcess.setCurrentIndex(self.preDecrypt.currentIndex())
        #

    def onDecryptMode(self):
        #
        self.buttonCryptMode.setChecked(False)
        self.buttonDecryptMode.setChecked(True)
        #
        self.linePasswordL.setDisabled(True)
        self.leftText.setReadOnly(True)
        self.linePasswordR.setDisabled(False)
        self.rightText.setReadOnly(False)
        #
        self.checkPwdL.setDisabled(True)
        self.checkPwdR.setDisabled(False)
        #
        if self.checkPwdR.isChecked():
            self.linePasswordR.setEchoMode(QtGui.QLineEdit.Normal)
        else:
            self.linePasswordR.setEchoMode(QtGui.QLineEdit.Password)
        #
        self.postDecrypt.setCurrentIndex(self.preProcess.currentIndex())
        self.comboDecrypt.setCurrentIndex(self.comboCrypt.currentIndex())
        self.preDecrypt.setCurrentIndex(self.postProcess.currentIndex())
        #

    def onLeftTextChanged(self):
        #
        if not self.buttonCryptMode.isChecked():
            return
        if not self.leftText.toPlainText():
            self.rightText.clear()
            return
        #
        # Save all pre/enc/post operations.
        pre = self.preProcess.currentText()
        enc = self.comboCrypt.currentText()
        post = self.postProcess.currentText()
        pwd = self.linePasswordL.text()
        tags = not self.setTags.isChecked()
        #
        if self.setFormatting.isChecked():
            # HTML string.
            try: txt = self.leftText.toHtml().encode('utf_8')
            except: txt = self.leftText.toHtml()
            # Cleanup HTML string.
            txt = re.sub('^.*<body.+?>', '', ' '.join(txt.split()))
            txt = txt.replace('</body>', '')
            txt = txt.replace('</html>', '')
            txt = txt.replace(' margin-top:0px;', '')
            txt = txt.replace(' margin-bottom:0px;', '')
            txt = txt.replace(' margin-left:0px;', '')
            txt = txt.replace(' margin-right:0px;', '')
            txt = txt.replace(' -qt-block-indent:0;', '')
            txt = txt.replace(' text-indent:0px;', '')
            txt = txt.replace(' style=""', '')
            txt = txt.strip()
        else:
            try: txt = self.leftText.toPlainText().encode('utf_8')
            except: txt = self.leftText.toPlainText()
        #
        # Setup default (no error) status.
        if self.buttonCryptMode.isChecked():
            self.statusBar.setStyleSheet('color: blue;')
            self.statusBar.showMessage('  Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
        #
        self.postDecrypt.setCurrentIndex(self.preProcess.currentIndex())
        self.comboDecrypt.setCurrentIndex(self.comboCrypt.currentIndex())
        self.preDecrypt.setCurrentIndex(self.postProcess.currentIndex())
        #
        # Encrypt the text.
        final = self.SE.encrypt(txt, pre, enc, post, pwd, tags)
        #
        if final:
            self.rightText.setPlainText(final)
            if self.setFormatting.isChecked():
                self.nrLettersL.setText('Html: %i' % len(txt))
            else:
                self.nrLettersL.setText('Text: %i' % len(txt))
            self.nrLettersR.setText('Enc: %i' % len(final))
        else:
            self.rightText.clear()
            self.statusBar.setStyleSheet('color: red;')
            self.statusBar.showMessage(self.SE.error)
        #

    def onRightTextChanged(self):
        #
        if not self.buttonDecryptMode.isChecked() or not self.rightText.toPlainText():
            return
        #
        txt = self.rightText.toPlainText()
        #
        try:
            info = re.search(NO_TAGS, txt).group(1)
            self.postDecrypt.setCurrentIndex( self.postDecrypt.findText(info.split(':')[0], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.comboDecrypt.setCurrentIndex( self.comboDecrypt.findText(info.split(':')[1], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.preDecrypt.setCurrentIndex( self.preDecrypt.findText(info.split(':')[2], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
        except:
            pass
        #
        # This must be right here.
        pre = self.preDecrypt.currentText()
        enc = self.comboDecrypt.currentText()
        post = self.postDecrypt.currentText()
        pwd = self.linePasswordR.text()
        #
        if self.buttonDecryptMode.isChecked():
            self.statusBar.setStyleSheet('color: blue;')
            self.statusBar.showMessage('  Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
        #
        self.preProcess.setCurrentIndex(self.postDecrypt.currentIndex())
        self.comboCrypt.setCurrentIndex(self.comboDecrypt.currentIndex())
        self.postProcess.setCurrentIndex(self.preDecrypt.currentIndex())
        #
        # Decrypt the text.
        final = self.SE.decrypt(txt, pre, enc, post, pwd)
        #
        if final:
            # Cleanup HTML string.
            final = re.sub('^.*<body.+?>', '', ' '.join(final.split()))
            final = final.replace('</body>', '')
            final = final.replace('</html>', '')
            final = final.replace(' margin-top:0px;', '')
            final = final.replace(' margin-bottom:0px;', '')
            final = final.replace(' margin-left:0px;', '')
            final = final.replace(' margin-right:0px;', '')
            final = final.replace(' -qt-block-indent:0;', '')
            final = final.replace(' text-indent:0px;', '')
            final = final.replace(' style=""', '')
            final = final.strip()
            # Setup string as HTML.
            try: self.leftText.setHtml(final.decode('utf_8'))
            except: self.leftText.setHtml(final)
            self.nrLettersL.setText('Dec: %i' % len(final))
            self.nrLettersR.setText('Enc: %i' % len(txt))
        else:
            self.leftText.clear()
            self.statusBar.setStyleSheet('color: red;')
            self.statusBar.showMessage(self.SE.error)
        #

    def onSave(self):
        #
        # Save all pre/enc/post operations.
        pre = self.preProcess.currentText()
        enc = self.comboCrypt.currentText()
        post = self.postProcess.currentText()
        #
        f = QtGui.QFileDialog()
        if post in ['Base64 Codec', 'Base32 Codec', 'HEX Codec']:
            path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'PNG Images (*.png)')
            ext = '.png'
        elif post=='UU Codec':
            path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'UU Files (*.uu)')
            ext = '.uu'
        elif post=='XML':
            path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'XML Files (*.xml)')
            ext = '.xml'
        else:
            path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'All files (*.*)')
            ext = ''
        if not path:
            return
        #
        # Save password.
        pwd = self.linePasswordL.text()
        # Text from rigth side.
        txt = self.rightText.toPlainText()
        # File extension.
        if not os.path.splitext(path)[1]:
            path += ext
        #
        # For PNG files.
        if ext=='.png':
            self.SE.toImage(txt, pre, enc, post, pwd, path, encrypt=False)
        else:
            open(path, 'w').write(txt)
        #

    def onLoad(self):
        #
        f = QtGui.QFileDialog()
        path = f.getOpenFileName(self, 'Load crypted text', os.getcwd(), 'All files (*.*)')
        if not path:
            return
        #
        val = self.SE._import(pre=None, enc=None, post=None, pwd=None, fpath=path, decrypt=False)
        #
        if val:
            self.rightText.setPlainText(val)
            self.onDecryptMode()
            self.onRightTextChanged()
        #

#

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())

# Eof()

