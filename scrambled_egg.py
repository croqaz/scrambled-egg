#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os, sys
import re, math
import string
import urllib
import binascii as ba
import base64
import json
import bz2, zlib
from collections import OrderedDict

from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Cipher import ARC2
from Crypto.Cipher import CAST
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA

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
ENC = OrderedDict([('AES', 'AES'), ('Blowfish', 'B'), ('ARC2', 'ARC'), ('CAST', 'CA'), ('DES3', 'D'), ('RSA', 'RSA'), ('None', 'N')])
ENCODE = ['Base64 Codec', 'Base32 Codec', 'HEX Codec', 'Quopri Codec', 'String Escape', 'UU Codec', 'Json', 'XML']
ENCODE_D = {'Base64 Codec':'64', 'Base32 Codec':'32', 'HEX Codec':'H', 'Quopri Codec':'Q', 'String Escape':'STR', 'UU Codec':'UU', 'Json':'JS', 'XML':'XML'}
NO_TAGS = re.compile(
    '<#>(?P<ts>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})</?#>|' \
    '\[#\](?P<tq>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\[#\]|' \
    '\{#\}(?P<ta>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\{#\}|' \
    '\(#\)(?P<tp>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\(#\)')
#
# These numbers are used when (re)creating PNG images.
SCRAMBLE_NR = {'None':'1', 'ROT13':'2', 'ZLIB':'3', 'BZ2':'4'}
ENCRYPT_NR = {'AES':'1', 'ARC2':'2', 'CAST':'3', 'Blowfish':'5', 'DES3':'4', 'None':'9'}
ENCODE_NR = {'Base64 Codec':'4', 'Base32 Codec':'2', 'HEX Codec':'1', 'Quopri Codec':'9', 'String Escape':'6', 'UU Codec':'8', 'XML':'7'}
#


class ScrambledEgg():

    def __init__(self):
        self.error = '' # Error string.
        self.fillChar = '\x01' # This is probably the best filling character.
        self.rsaFillChar = (unichr(2662)*2).encode('utf')
        self.pre = ''   # Current operations, in order.
        self.enc = ''
        self.post = ''

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
        '''
        Adapt the password for each encryption. \n\
        AES accepts maxim 32 characters. \n\
        ARC2 accepts maxim 128 characters. \n\
        CAST accepts maxim 8 characters. \n\
        Blowfish accepts maxim 56 characters. \n\
        DES3 accepts maxim 24 characters.
        '''
        #
        L = len(pwd)

        if enc == 'AES' or enc == ENC['AES']:
            key_size = 32

        elif enc == 'Blowfish' or enc == ENC['Blowfish']:
            key_size = 56

        elif enc == 'ARC2' or enc == ENC['ARC2']:
            key_size = 128

        elif enc == 'CAST' or enc == ENC['CAST']:
            key_size = 8

        elif enc == 'DES3' or enc == ENC['DES3']:
            key_size = 24

        elif enc == 'RSA':
            # Read the public/ private key from file and return.
            return open(pwd, 'rb').read()

        elif not pwd:
            # Only for NULL passwords.
            return 'X'

        key = ''
        md_hash = MD5.new(pwd)

        # Scramble password many times.
        for i in range(666):
            key += md_hash.digest()
            md_hash.update(key)

        # The password for encryption.
        return key[-key_size:]
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
        # Check RSA key path.
        if enc == 'RSA' and not os.path.exists(pwd):
            self.__error(2, pre, enc, post, field='L')
            return
        #
        pwd = self._fix_password(pwd, enc)
        #
        # No need to pad text for RSA.
        if enc != 'RSA':
            L = len(txt)
            txt += self.fillChar * ( (((L/16)+1)*16) - L )
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
        elif enc == 'RSA':
            o = RSA.importKey(pwd)
            # Damn it, this operation is very slow.
            b64_txt = ba.b2a_base64(txt)
            to_join = []
            step = 0
            while 1:
                # Read 128 characters at a time.
                s = b64_txt[step*128:(step+1)*128]
                if not s: break
                # Encrypt with RSA and append the result to list.
                to_join.append(o.encrypt(s, 0)[0])
                step += 1
            # Join the results.
            encrypted = self.rsaFillChar.join(to_join)
            del b64_txt, to_join, step
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
        elif post == 'Json':
            if tags:
                final = json.dumps({'tags':('<#>%s:%s:%s</#>' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post])), 'data':ba.b2a_base64(encrypted)})
            else:
                final = json.dumps({'data':ba.b2a_base64(encrypted)})
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
        # Trying to identify and/or delete pre/enc/post tags.
        try:
            re_groups = re.search(NO_TAGS, txt).groups()
            tags = re_groups[0] or re_groups[1] or re_groups[2] or re_groups[3]
            txt = re.sub(NO_TAGS, '', txt)
            # Identify here.
            if not pre:
                pre = tags.split(':')[2]
                self.pre = pre
            if not enc:
                enc = tags.split(':')[1]
                self.enc = enc
            if not post:
                post = tags.split(':')[0]
                self.post = post
        except:
            pass
        #
        # Check RSA key path.
        if enc == 'RSA' and not os.path.exists(pwd):
            self.__error(2, pre, enc, post)
            return
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
        elif pre == 'String Escape' or pre == ENCODE_D['String Escape']:
            try: txt = txt.decode('string_escape')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'UU Codec' or pre == ENCODE_D['UU Codec']:
            try: txt = txt.decode('uu')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Json' or pre == ENCODE_D['Json']:
            try:
                txt = json.loads(txt)
                txt = ba.a2b_base64(txt['data'])
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
        elif enc == 'RSA':
            o = RSA.importKey(pwd)
        elif not enc or enc == 'None':
            txt = txt.rstrip(self.fillChar)
        else:
            raise Exception('Invalid decrypt "%s" !' % enc)
        #
        if enc == 'RSA':
            # RSA decryption is really slooooow.
            try:
                to_decrypt = txt.split(self.rsaFillChar)
                to_join = []
                for s in to_decrypt:
                    to_join.append(o.decrypt(s))
                # Join the chunks.
                txt = ba.a2b_base64(''.join(to_join))
                del to_join, to_decrypt
            except: self.__error(2, pre, enc, post) ; return
        #
        elif enc != 'None':
            try: txt = o.decrypt(txt).rstrip(self.fillChar)
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
        Any information, text and/or files, can be encoded inside a little PNG image. \n\
        Depending on how you encode the crypted data, images come in 3 flavors: HEX, Base32 and Base64. \n\
        Normally each letter can be transformed into a color from 1 to 255 ; so 4 colors become one pixel. \n\
        HEX encoding is `high density`. Two letters are transformed into a color from 1 to 255,
        so one pixel consists of 8 letters, instead of 4 letters.
        '''
        #
        # Input can be string, or file. If's file, read it.
        if str(type(txt)) == "<type 'file'>":
            txt.seek(0)
            txt = txt.read()

        # Strip pre/enc/post tags.
        txt = re.sub(NO_TAGS, '', txt)

        # All text must be reversed, to pop from the end of the characters list.
        if encrypt: # If text MUST be encrypted first, encrypt without pre/enc/post tags.
            val = self.encrypt(txt, pre, enc, post, pwd, False)[::-1]
            if not val:
                return
        else: # Else, the text is already encrypted.
            val = txt[::-1]

        # Calculate the edge of the square and blank square.
        if post == 'HEX Codec':
            # Length.
            edge = math.ceil(math.sqrt( float(len(val) + 1)/8.0 ))
            blank = math.ceil(edge * edge - float(len(val)) / 8.0)
            if blank:
                blank -= 1
        else:
            # Length + 5, just to make sure there are enough blank pixels.
            edge = math.ceil(math.sqrt( float(len(val) + 5)/4.0 ))
            blank = math.ceil((edge * edge - float(len(val))/4.0) / 2.0)

        # `Second pixel` : a number representing the length of valid characters.
        # This is only used for HEX, because when decrypting, this number of letters is trimmed from the end of the string.
        if post == 'HEX Codec':
            second_pixel = str(QtGui.QColor(int(blank)).name())[3:]
            val += second_pixel[::-1]
            #print '! Second pixel', second_pixel
            del second_pixel

        # `First pixel` : a string with 4 numbers representing Pre/ Enc/ Post information.
        # For Base64/ Base32, this variabile is encoded in one pixel (4 characters).
        # For HEX, First Pixel + Second Pixel are both encoded in one pixel (8 characters).
        if post == 'HEX Codec':
            first_pixel = '0'
        else:
            first_pixel = '1'

        # Add first pixel at the end of the reversed string.
        first_pixel += SCRAMBLE_NR[pre] + ENCRYPT_NR[enc] + ENCODE_NR[post]
        val += first_pixel[::-1]
        #print '! First pixel', first_pixel
        del first_pixel

        # Explode the encrypted string.
        list_val = list(val)
        # Creating new square image.
        print('Creating img, %ix%i, blank : %i, string to encode : %i chars.' % (edge, edge, blank, len(val)))
        im = QtGui.QImage(edge, edge, QtGui.QImage.Format_ARGB32)
        _pix = im.setPixel
        _rgba = QtGui.qRgba
        _int = int
        _ord = ord

        # HEX codec.
        if post == 'HEX Codec':
            for i in range(int(edge)):
                for j in range(int(edge)):
                    #
                    _r = _g = _b = _a = 255

                    # Red
                    if len(list_val) >= 2:
                        _r = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _r = _int(list_val.pop(), 16)

                    # Green
                    if len(list_val) >= 2:
                        _g = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _g = _int(list_val.pop(), 16)

                    # Blue
                    if len(list_val) >= 2:
                        _b = _int(list_val.pop()+list_val.pop(), 16)
                    elif len(list_val) == 1:
                        _b = _int(list_val.pop(), 16)

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

                    if len(list_val) >= 1:
                        _r = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _g = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _b = _ord(list_val.pop())
                    if len(list_val) >= 1:
                        _a = _ord(list_val.pop())

                    _pix(j, i, _rgba(_r, _g, _b, _a))
                    #

        #
        try:
            im.save(path, 'PNG', -1)
        except:
            print('Cannot save PNG file "%s" !' % path)
        #

    def fromImage(self, pwd, path, decrypt=True):
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

        list_val = []
        _pix = im.pixel
        _r = QtGui.qRed
        _g = QtGui.qGreen
        _b = QtGui.qBlue
        _a = QtGui.qAlpha

        fp_val = 0

        # Calculate First Pixel.
        for i in range(im.width()):
            for j in range(im.height()):
                #
                if fp_val:
                    break
                #
                pix1 = _pix(j, i)
                #
                if pix1 != 4294967295L: # Color #FFFFFFFF, completely white pixel.
                    fp_val = [_r(pix1), _g(pix1), _b(pix1), _a(pix1)]
                    break
                #

        # Calculate the colors of first pixel.
        # For HEX: Red+Green represents pre/enc/post information and Blue+Alpha value represents nr of valid characters.
        # For Base64/ Base32, first pixel represents only the Pre/ Enc/ Post information.
        cc = QtGui.QColor(fp_val[0], fp_val[1], fp_val[2], fp_val[3])
        first_pixel_hex = cc.name()[1:5]
        first_pixel_b = [chr(fp_val[0]), chr(fp_val[1]), chr(fp_val[2]), chr(fp_val[3])]
        if cc.alpha() < 16:
            blank = int(hex(cc.blue())[2:]+'0'+hex(cc.alpha())[2:], 16)
        else:
            blank = int(hex(cc.blue())[2:]+hex(cc.alpha())[2:], 16)

        # Reverse number dictionaries.
        reverse_s = dict(zip(SCRAMBLE_NR.values(), SCRAMBLE_NR.keys()))
        reverse_ey = dict(zip(ENCRYPT_NR.values(), ENCRYPT_NR.keys()))
        reverse_ed = dict(zip(ENCODE_NR.values(), ENCODE_NR.keys()))

        if first_pixel_hex[0] == '0' and first_pixel_b[0] != '0':
            post = reverse_s[first_pixel_hex[1]]
            enc = reverse_ey[first_pixel_hex[2]]
            pre = reverse_ed[first_pixel_hex[3]]
        else:
            post = reverse_s[first_pixel_b[1]]
            enc = reverse_ey[first_pixel_b[2]]
            pre = reverse_ed[first_pixel_b[3]]

        # Save Pre/ Enc/ Post information for GUI.
        self.pre = pre
        self.enc = enc
        self.post = post

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
                            list_val.append('0'+hex(v)[-1])
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

        # Fix `blank` value.
        if blank:
            blank = - blank * 8
        else:
            blank = len(list_val) * 8

        # Used for DEBUG.
        #ff = open('dump.txt', 'wb')
        #ff.write('\nColor: %s ; FP Val: %s ; FP Hex: %s ; FP B64/32: %s ; Blank: %i' % (cc.name(),str(fp_val),first_pixel_hex,''.join(first_pixel_b),blank))
        #ff.write('\n'+''.join(list_val)+'\n')
        #ff.write(''.join(list_val)[8:blank])
        #ff.close() ; del ff, cc, fp_val

        # If the text MUST be decrypted.
        if decrypt:
            if pre == 'HEX Codec':
                val = self.decrypt(''.join(list_val)[8:blank], pre, enc, post, pwd)
            else:
                val = self.decrypt(''.join(list_val[4:]), pre, enc, post, pwd)

            if not val:
                print('Error from image (decrypt)! ' + self.error.strip())
            else:
                return val

        # Else, don't decrypt.
        else:
            if pre == 'HEX Codec':
                val = ''.join(list_val)[8:blank]
            else:
                val = ''.join(list_val[4:])

            if not val:
                print('Error from image (no decrypt)!')
            else:
                return val
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
            return self.fromImage(pwd, fpath, decrypt)
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


STYLE_BUTTON = '''
QPushButton {color:#2E2633; background-color:#E1EDB9;}
QPushButton:checked {color:#555152; background-color:#F3EFEE;}
QPushButton::hover {color:#99173C;}
'''

STYLE_CHECKBOX = '''
QCheckBox {color:#2E2633;}
QCheckBox::hover {color:#99173C;}
'''

STYLE_LINEEDIT = '''
QLineEdit {background-color:#E1EDB9; border:1px solid #A59D95; border-radius:4px;}
QLineEdit:disabled {background-color:#EFEBE7;}
QLineEdit:focus {border:1px solid #99173C;}
'''

STYLE_TEXTEDIT = '''
QTextEdit {background-color:#E1EDB9; border:1px solid #A59D95; border-radius:4px;}
QTextEdit:disabled {color:#555152; background-color:#EFEBE7;}
QTextEdit:focus {border:1px solid #99173C;}
QPlainTextEdit {background-color:#E1EDB9; border:1px solid #A59D95; border-radius:4px;}
QPlainTextEdit:disabled {color:#555152; background-color:#EFEBE7;}
QPlainTextEdit:focus {border:1px solid #99173C;}
'''

STYLE_COMBOBOX = '''
QComboBox {color:#2E2633;}
QComboBox QAbstractItemView {selection-background-color:#E1EDB9;}
'''


class Window(QtGui.QMainWindow):

    def __init__(self):
        '''
        Init function.
        '''
        super(Window, self).__init__()
        self.resize(800, 400)
        self.setWindowTitle('Scrambled Egg :: Live Crypt')
        self.setWindowIcon(QtGui.QIcon(os.getcwd() + '/icon.ico'))
        QtGui.QApplication.setStyle(QtGui.QStyleFactory.create('CleanLooks'))
        QtGui.QApplication.setPalette(QtGui.QApplication.style().standardPalette())
        self.setAcceptDrops(True)
        self.SE = ScrambledEgg()

        self.centralWidget = QtGui.QWidget(self) # Central Widget.
        self.setCentralWidget(self.centralWidget)

        self.statusBar = QtGui.QStatusBar(self)  # Status Bar.
        self.setStatusBar(self.statusBar)
        self.layout = QtGui.QGridLayout(self.centralWidget) # Main Layout.
        self.centralWidget.setLayout(self.layout)

        self.leftText = QtGui.QTextEdit(self.centralWidget)       # To write clean text.
        self.rightText = QtGui.QPlainTextEdit(self.centralWidget) # To view encrypted text.

        self.buttonCryptMode = QtGui.QPushButton(self.centralWidget)
        self.buttonDecryptMode = QtGui.QPushButton(self.centralWidget)

        self.preProcess = QtGui.QComboBox(self.centralWidget)  # Left side.
        self.comboCrypt = QtGui.QComboBox(self.centralWidget)  # Left side.
        self.postProcess = QtGui.QComboBox(self.centralWidget) # Left side.
        self.linePasswordL = QtGui.QLineEdit(self.centralWidget) # Left side.
        self.checkPwdL = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Left side.
        self.nrLettersL = QtGui.QLabel('', self.centralWidget) # Left side.
        self.setFormatting = QtGui.QCheckBox('Formatted text', self.centralWidget) # Left side.
        self.showHTML = QtGui.QCheckBox('Show HTML', self.centralWidget) # Left side.
        self.setTags = QtGui.QCheckBox('No tags', self.centralWidget) # Left side.

        self.preDecrypt = QtGui.QComboBox(self.centralWidget)    # Right side.
        self.comboDecrypt = QtGui.QComboBox(self.centralWidget)  # Right side.
        self.postDecrypt = QtGui.QComboBox(self.centralWidget)   # Right side.
        self.linePasswordR = QtGui.QLineEdit(self.centralWidget) # Right side.
        self.checkPwdR = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Right side.
        self.nrLettersR = QtGui.QLabel('', self.centralWidget) # Right side.
        self.loadFile = QtGui.QPushButton('Import', self.centralWidget) # Right side.
        self.saveFile = QtGui.QPushButton('Export', self.centralWidget) # Right side.
        self.helpButton = QtGui.QPushButton('Help !', self.centralWidget) # Right side.

        self.layout.addWidget(self.buttonCryptMode, 1, 1, 1, 5)
        self.layout.addWidget(self.buttonDecryptMode, 1, 6, 1, 5)

        self.layout.addWidget(self.preProcess, 2, 1, 1, 1)
        self.layout.addWidget(self.comboCrypt, 2, 2, 1, 1)
        self.layout.addWidget(self.postProcess, 2, 3, 1, 1)
        self.layout.addWidget(self.preDecrypt, 2, 6, 1, 1)
        self.layout.addWidget(self.comboDecrypt, 2, 7, 1, 1)
        self.layout.addWidget(self.postDecrypt, 2, 8, 1, 1)
        self.layout.addWidget(self.setFormatting, 21, 1, 1, 1)
        self.layout.addWidget(self.showHTML, 21, 2, 1, 1)
        self.layout.addWidget(self.setTags, 21, 3, 1, 1)

        self.layout.addWidget(self.loadFile, 21, 6, 1, 1)
        self.layout.addWidget(self.saveFile, 21, 7, 1, 1)
        self.layout.addWidget(self.helpButton, 21, 10, 1, 1)

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
        self.buttonCryptMode.setStyleSheet(STYLE_BUTTON)
        self.buttonDecryptMode.setCheckable(True)
        self.buttonDecryptMode.setToolTip('Switch to Decryption mode')
        self.buttonDecryptMode.setStyleSheet(STYLE_BUTTON)
        self.helpButton.setStyleSheet(STYLE_BUTTON)

        # Some styles.
        self.loadFile.setStyleSheet(STYLE_BUTTON)
        self.saveFile.setStyleSheet(STYLE_BUTTON)
        self.leftText.setStyleSheet(STYLE_TEXTEDIT)
        self.rightText.setStyleSheet(STYLE_TEXTEDIT)

        # Password fields.
        self.linePasswordL.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordL.setToolTip('Password used for encrypting the text')
        self.linePasswordL.setMaxLength(99)
        self.linePasswordL.setStyleSheet(STYLE_LINEEDIT)
        self.checkPwdL.setTristate(False)
        self.checkPwdL.setStyleSheet(STYLE_CHECKBOX)
        self.linePasswordR.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordR.setToolTip('Password used for decrypting the text')
        self.linePasswordR.setMaxLength(99)
        self.linePasswordR.setDisabled(True)
        self.linePasswordR.setStyleSheet(STYLE_LINEEDIT)
        self.checkPwdR.setTristate(False)
        self.checkPwdR.setStyleSheet(STYLE_CHECKBOX)

        # Formatted text.
        self.setFormatting.setTristate(False)
        self.setFormatting.setToolTip('Encrypt this text as HTML')
        self.setFormatting.setStyleSheet(STYLE_CHECKBOX)
        self.setTags.setTristate(False)
        self.setTags.setToolTip('Strip pre/enc/post tags')
        self.setTags.setStyleSheet(STYLE_CHECKBOX)
        self.showHTML.setTristate(False)
        self.showHTML.setToolTip('Toogle view HTML source behind the formatted text')
        self.showHTML.setStyleSheet(STYLE_CHECKBOX)

        # All combo boxes.
        MIN = 120
        self.preProcess.setMinimumWidth(MIN)
        self.preProcess.setStyleSheet(STYLE_COMBOBOX)
        self.comboCrypt.setMinimumWidth(MIN)
        self.comboCrypt.setStyleSheet(STYLE_COMBOBOX)
        self.postProcess.setMinimumWidth(MIN)
        self.postProcess.setStyleSheet(STYLE_COMBOBOX)
        self.preDecrypt.setMinimumWidth(MIN)
        self.preDecrypt.setStyleSheet(STYLE_COMBOBOX)
        self.comboDecrypt.setMinimumWidth(MIN)
        self.comboDecrypt.setStyleSheet(STYLE_COMBOBOX)
        self.postDecrypt.setMinimumWidth(MIN)
        self.postDecrypt.setStyleSheet(STYLE_COMBOBOX)

        # Pre combo-boxes.
        self.preProcess.setToolTip('Select pre-process')
        self.postDecrypt.setToolTip('Select post-decrypt')
        for scramble in SCRAMBLE:
            self.preProcess.addItem(scramble, scramble)
            self.postDecrypt.addItem(scramble, scramble)

        # Encryption/ decryption combo-boxes.
        self.comboCrypt.setToolTip('Select encryption algorithm; it will use the provided password')
        self.comboDecrypt.setToolTip('Select encryption algorithm; it will use the provided password')
        for enc in ENC.keys():
            self.comboCrypt.addItem(enc, enc)
            self.comboDecrypt.addItem(enc, enc)

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
        self.checkPwdL.stateChanged.connect(lambda x: \
            self.linePasswordL.setEchoMode(QtGui.QLineEdit.Normal) if self.checkPwdL.isChecked() \
            else self.linePasswordL.setEchoMode(QtGui.QLineEdit.Password))
        self.buttonCryptMode.clicked.connect(self.onCryptMode)
        #
        self.linePasswordR.textChanged.connect(self.onRightTextChanged)
        self.rightText.textChanged.connect(self.onRightTextChanged)
        self.checkPwdR.stateChanged.connect(lambda x: \
            self.linePasswordR.setEchoMode(QtGui.QLineEdit.Normal) if self.checkPwdR.isChecked() \
            else self.linePasswordR.setEchoMode(QtGui.QLineEdit.Password))
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
        self.helpButton.clicked.connect(self.onHelp)
        self.setFormatting.toggled.connect(self.onLeftTextChanged)
        self.setTags.toggled.connect(self.onLeftTextChanged)
        self.showHTML.toggled.connect(self.toggleHtml)
        #
        # ACTION !
        self.onCryptMode()
        #

    def dragEnterEvent(self, e):
        #
        mime_data = e.mimeData()

        # Accept plain text, HTML text and file paths.
        if mime_data.hasHtml() or mime_data.hasText() or mime_data.hasFormat('text/uri-list'):
            e.accept()
        else:
            e.ignore()
        #

    def dropEvent(self, e):
        #
        mime_data = e.mimeData()

        if mime_data.hasFormat('text/html'):
            dataf = mime_data.html()
            self.leftText.setHtml(dataf)

        elif mime_data.hasFormat('text/plain'):
            dataf = mime_data.text()
            self.leftText.setPlainText(dataf)

        elif mime_data.hasFormat('text/uri-list'):
            uri = mime_data.data('text/uri-list')
            uris = str(uri).split('\r\n')[:-1]
            # List of dragged files.
            for url in uris:
                print urllib.urlopen(url)
        #

    def onCryptMode(self):
        #
        self.buttonCryptMode.setChecked(True)
        self.buttonCryptMode.setText('Encrypt Mode is Enabled')
        self.buttonDecryptMode.setChecked(False)
        self.buttonDecryptMode.setText('Decrypt Mode')
        #
        self.linePasswordL.setDisabled(False)
        self.leftText.setDisabled(False)
        #
        self.linePasswordR.setDisabled(True)
        self.rightText.setDisabled(True)
        #
        self.checkPwdL.setDisabled(False)
        self.checkPwdR.setDisabled(True)
        #
        self.preProcess.setCurrentIndex(self.postDecrypt.currentIndex())
        self.comboCrypt.setCurrentIndex(self.comboDecrypt.currentIndex())
        self.postProcess.setCurrentIndex(self.preDecrypt.currentIndex())
        #

    def onDecryptMode(self):
        #
        self.buttonCryptMode.setChecked(False)
        self.buttonCryptMode.setText('Encrypt Mode')
        self.buttonDecryptMode.setChecked(True)
        self.buttonDecryptMode.setText('Decrypt Mode is Enabled')
        #
        self.linePasswordL.setDisabled(True)
        self.leftText.setDisabled(True)
        #
        self.linePasswordR.setDisabled(False)
        self.rightText.setDisabled(False)
        #
        self.checkPwdL.setDisabled(True)
        self.checkPwdR.setDisabled(False)
        #
        self.postDecrypt.setCurrentIndex(self.preProcess.currentIndex())
        self.comboDecrypt.setCurrentIndex(self.comboCrypt.currentIndex())
        self.preDecrypt.setCurrentIndex(self.postProcess.currentIndex())
        #

    def cleanupHtml(self, txt):
        #
        txt = re.sub('''<span style="[0-9a-zA-Z "':;,-]+">([<>br/ ])</span>''', '', ' '.join(txt.split())) # Kill empty span.
        txt = re.sub('''<p style="[0-9a-zA-Z "':;,-]+">[ ]?</p>''', '', txt) # Kill empty paragraphs.
        txt = txt.replace('> <p style', '><p style')
        txt = txt.replace('>  <p style', '><p style')
        txt = txt.replace('</td> <td>', '</td><td>')
        txt = txt.replace('</tr> <tr>', '</tr><tr>')
        txt = txt.replace('</span> </p>', '</span></p>')
        txt = txt.replace('</p> <p ', '</p>\n<p ')
        txt = txt.replace(' margin-top:0px;', '') # Delete obsolete styles.
        txt = txt.replace(' margin-bottom:0px;', '')
        txt = txt.replace(' margin-left:0px;', '')
        txt = txt.replace(' margin-right:0px;', '')
        txt = txt.replace(' -qt-block-indent:0;', '')
        txt = txt.replace(' text-indent:0px;', '')
        txt = txt.replace(' style=""', '') # Delete empty style.
        return txt.strip()
        #

    def toggleHtml(self):
        #
        if self.showHTML.isChecked():
            txt = self.leftText.toHtml()
            self.leftText.clear()
            self.leftText.setFontFamily("Verdana")
            self.leftText.setFontItalic(False)
            self.leftText.setFontUnderline(False)
            self.leftText.setFontWeight(10)
            self.leftText.setFontPointSize(10)
            self.leftText.setTextColor(QtGui.QColor())
            self.leftText.setPlainText(self.cleanupHtml(txt))
        else:
            txt = self.leftText.toPlainText()
            self.leftText.clear()
            self.leftText.setHtml(self.cleanupHtml(txt))
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
        # If encryption mode is RSA, reveal key path.
        if enc=='RSA':
            self.checkPwdL.setChecked(True)
            self.checkPwdL.setText('<- Path')
        else:
            self.checkPwdL.setText('<- Pwd')
        #
        if self.setFormatting.isChecked() and not self.showHTML.isChecked():
            # HTML string.
            try: txt = self.leftText.toHtml().encode('utf_8')
            except: txt = self.leftText.toHtml()
            # Cleanup HTML string.
            txt = self.cleanupHtml(txt)
        else:
            try: txt = self.leftText.toPlainText().encode('utf_8')
            except: txt = self.leftText.toPlainText()
        #
        # Setup default (no error) status.
        if self.buttonCryptMode.isChecked():
            self.statusBar.setStyleSheet('color:blue')
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
            self.statusBar.setStyleSheet('color:red')
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
            tags = re.search(NO_TAGS, txt).group(1)
            self.postDecrypt.setCurrentIndex( self.postDecrypt.findText(tags.split(':')[0], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.comboDecrypt.setCurrentIndex( self.comboDecrypt.findText(tags.split(':')[1], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.preDecrypt.setCurrentIndex( self.preDecrypt.findText(tags.split(':')[2], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
        except:
            pass
        #
        # This must be right here.
        pre = self.preDecrypt.currentText()
        enc = self.comboDecrypt.currentText()
        post = self.postDecrypt.currentText()
        pwd = self.linePasswordR.text()
        #
        # If encryption mode is RSA, reveal key path.
        if enc=='RSA':
            self.checkPwdR.setChecked(True)
            self.checkPwdR.setText('<- Path')
        else:
            self.checkPwdR.setText('<- Pwd')
        #
        if self.buttonDecryptMode.isChecked():
            self.statusBar.setStyleSheet('color:blue')
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
            final = self.cleanupHtml(final)
            # Setup string as HTML.
            try: self.leftText.setHtml(final.decode('utf_8'))
            except: self.leftText.setHtml(final)
            self.nrLettersL.setText('Dec: %i' % len(final))
            self.nrLettersR.setText('Enc: %i' % len(txt))
        else:
            self.leftText.clear()
            self.statusBar.setStyleSheet('color:red')
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

        # Import the text from file, without decryption.
        val = self.SE._import(pre=None, enc=None, post=None, pwd=None, fpath=path, decrypt=False)

        if val:
            # For step 1.
            self.preProcess.setCurrentIndex( self.preProcess.findText(self.SE.post, QtCore.Qt.MatchFlag(QtCore.Qt.MatchFixedString)) )
            self.postDecrypt.setCurrentIndex( self.postDecrypt.findText(self.SE.post, QtCore.Qt.MatchFlag(QtCore.Qt.MatchFixedString)) )
            # For step 2.
            self.comboCrypt.setCurrentIndex( self.comboCrypt.findText(self.SE.enc, QtCore.Qt.MatchFlag(QtCore.Qt.MatchFixedString)) )
            self.comboDecrypt.setCurrentIndex( self.comboDecrypt.findText(self.SE.enc, QtCore.Qt.MatchFlag(QtCore.Qt.MatchFixedString)) )
            # For step 3.
            self.postProcess.setCurrentIndex( self.postProcess.findText(self.SE.pre, QtCore.Qt.MatchFlag(QtCore.Qt.MatchFixedString)) )
            self.preDecrypt.setCurrentIndex( self.preDecrypt.findText(self.SE.pre, QtCore.Qt.MatchFlag(QtCore.Qt.MatchFixedString)) )

            self.rightText.setPlainText(val)
            self.onDecryptMode()
            self.onRightTextChanged()
            self.rightText.setFocus()
        #

    def onHelp(self):
        #
        QtGui.QMessageBox.about(self.centralWidget, 'Scrambled Egg Help',
            '<br><b>Copyright (C) 2010-2011</b> : Cristi Constantin. All rights reserved.<br>'
            '<b>Website</b> : http://scrambled-egg.googlecode.com/<br><br>'
            'Scrambled-Egg is a software designed for encrypting your sensitive data.<br>'
            'This is done in <font color="blue"><b>3 steps</b></font> : <i>pre encryption</i>, <i>encryption</i>, and <i>post encryption</i>.<br>'
            'The input data can be : plain text, formatted text, or a binary file.<br><br>'
            '<font color="blue"><b>Step 1</b></font> can compress your data using <b>ZLIB</b>, or <b>BZ2</b>. This step is optional.<br>'
            '<font color="blue"><b>Step 2</b></font> is the real encryption, for example with <b>AES</b>, or <b>Blowfish</b>. '
            'The password is used only in this step. '
            'For <b>RSA</b> encryption, instead of the password, you have to type the path to the public or private RSA key.<br>'
            '<font color="blue"><b>Step 3</b></font> will encode your data. This step is required, the rest are optional. '
            'There are a lot of encodings available, for example <b>Base64</b>, or <b>HEX</b>.<br><br>'
            'This FREE program is distributed in the hope that it will be useful.<br><br>'
            'Enjoy!')
        #

#

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())

# Eof()
