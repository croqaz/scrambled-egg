#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os, sys
import re, math
import string
import struct
import base64
import json
import bz2, zlib

import binascii as ba
try: from collections import OrderedDict
except: OrderedDict = dict

try: import Image
except: Image = None

from Crypto.Cipher import AES
from Crypto.Cipher import ARC2
from Crypto.Cipher import CAST
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2

#
ROT = string.maketrans('nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
#
SCRAMBLE = ['None', 'ROT13', 'ZLIB', 'BZ2']
SCRAMBLE_D = {'None':'N', 'ROT13':'R', 'ZLIB':'ZL', 'BZ2':'BZ'}
ENC = OrderedDict([('AES', 'AES'), ('Blowfish', 'B'), ('ARC2', 'ARC'), ('CAST', 'CA'), ('DES3', 'D'), ('RSA', 'RSA'), ('None', 'N')])
ENCODE = ['Base64 Codec', 'Base32 Codec', 'HEX Codec', 'Quopri Codec', 'Json', 'XML']
ENCODE_D = {'Base64 Codec':'64', 'Base32 Codec':'32', 'HEX Codec':'H', 'Quopri Codec':'Q', 'Json':'JS', 'XML':'XML'}
#
NO_TAGS = re.compile(
    '<#>(?P<ts>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})</?#>|' \
    '\[#\](?P<tq>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\[#\]|' \
    '\{#\}(?P<ta>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\{#\}|' \
    '\(#\)(?P<tp>[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3}:[0-9a-zA-Z ]{1,3})\(#\)|' \
    '(?P<tx><pre>[0-9a-zA-Z ]{1,3}</pre>\s*?<enc>[0-9a-zA-Z ]{1,3}</enc>\s*?<post>[0-9a-zA-Z ]{1,3}</post>)|' \
    '(?P<tj>"pre": "[0-9a-zA-Z ]{1,3}",\s*?"enc": "[0-9a-zA-Z ]{1,3}",\s*?"post": "[0-9a-zA-Z ]{1,3}")')
#
# These numbers are used when (re)creating PNG images.
SCRAMBLE_NR = {'None':'1', 'ROT13':'2', 'ZLIB':'3', 'BZ2':'4'}
ENCRYPT_NR = {'AES':'1', 'ARC2':'2', 'CAST':'3', 'Blowfish':'5', 'DES3':'4', 'RSA':'6', 'None':'9'}
ENCODE_NR = {'Base64 Codec':'4', 'Base32 Codec':'2', 'HEX Codec':'1', 'Quopri Codec':'9', 'XML':'7'}
#
__version__ = 'ver 0.5'
#

def findg(g):
    for i in g:
        if i: return ''.join(i.split())

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----
#       Scrambled-Egg  Encryption  Engine
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

class ScrambledEgg():

    def __init__(self):
        self.error = '' # Error string.
        self.pre = ''   # Current operations, in order.
        self.enc = ''
        self.post = ''
        self.rsa_path = ''

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

        if field=='R':
            self.error = '  Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post)
        else:
            self.error = '  Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post)
        #

    def _fix_password(self, pwd, enc):
        '''
        Scramble and adapt the password for each encryption. \n\
        AES accepts maxim 32 characters. \n\
        ARC2 accepts maxim 128 characters. \n\
        CAST accepts maxim 8 characters. \n\
        Blowfish accepts maxim 56 characters. \n\
        DES3 accepts maxim 24 characters.
        '''
        #
        # Accepting ANY type of password.
        pwd = ba.b2a_base64(pwd)

        if type(enc) == type(''):
            enc = enc.decode()

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

        elif enc == 'RSA' and self.rsa_path:
            key_size = 56
            # Read the public/ private key from file, encrypt password and return.
            rsa_key = open(self.rsa_path, 'rb').read()
            o = RSA.importKey(rsa_key)
            # RSA text is max 128 characters.
            rsa_pwd = pwd[:128]
            pwd = o.encrypt(rsa_pwd, 0)[0]
            del o, rsa_key, rsa_pwd

        elif not enc or enc == 'None':
            return pwd

        else:
            raise Exception('Fix password: Invalid encryption mode "%s" !' % enc)

        if not pwd:
            # Only for NULL passwords.
            return key_size * 'X'

        # Scramble the password many times.
        # Can't use random salt, 'cose the same pass must be recreated for decryption.
        hash_key = PBKDF2(password=pwd, salt='scregg', dkLen=128, count=1024)

        # The password for encryption/ decryption.
        # This is very strong, binary data!
        return hash_key[:key_size]
        #

    def guess_pre_enc_post(self, txt):

        # Trying to identify and/or delete pre/enc/post tags.
        re_groups = re.search(NO_TAGS, txt).groups()
        tags = findg(re_groups)

        # If Json.
        if '{' in txt and '}' in txt and '"data":' in txt:
            pre = 'Json'
            temp = json.loads(txt.decode())
            enc = temp.get('enc').encode()
            post = temp.get('pre').encode()
            del temp

        # If XML.
        elif '<data>' in txt and '</data>' in txt:
            pre = 'XML'
            enc = re.search('<enc>([0-9a-zA-Z ]{1,3})</enc>', tags).group(1)
            post = re.search('<pre>([0-9a-zA-Z ]{1,3})</pre>', tags).group(1)

        else:
            pre = tags.split(':')[2]
            enc = tags.split(':')[1]
            post = tags.split(':')[0]

        self.pre = {ENCODE_D[k]:k for k in ENCODE_D}.get(pre) or pre
        self.enc = {ENC[k]:k for k in ENC}.get(enc) or enc
        self.post = {SCRAMBLE_D[k]:k for k in SCRAMBLE_D}.get(post) or post

    def encrypt(self, txt, pre, enc, post, pwd, tags=True):
        #
        if type(txt) != type('') and type(txt) != type(u''):
            raise TypeError('Invalid data type for encryption: "%s" !' % str(type(txt)))
        #
        # Scramble operation.
        if pre in ['None', 'None']:
            pass
        elif pre in ['ZLIB', 'ZLIB']:
            txt = zlib.compress(txt)
        elif pre in ['BZ2', 'BZ2']:
            txt = bz2.compress(txt)
        elif pre in ['ROT13', 'ROT13']:
            txt = string.translate(txt, ROT)
        else:
            raise Exception('Invalid scramble "%s" !' % pre)
        #
        # Check RSA key path.
        if enc in ['RSA', 'RSA'] and not os.path.exists(self.rsa_path):
            print('RSA encryption must specify a valid path !')
            self.__error(2, pre, enc, post, field='L')
            return
        #
        pwd = self._fix_password(pwd, enc)
        #
        if enc in ['AES', 'AES']:
            o = AES.new(pwd, mode=2)
        elif enc in ['ARC2', 'ARC2']:
            o = ARC2.new(pwd, mode=2)
        elif enc in ['CAST', 'CAST']:
            o = CAST.new(pwd, mode=2)
        elif enc in ['Blowfish', 'Blowfish']:
            o = Blowfish.new(pwd, mode=2)
        elif enc in ['DES3', 'DES3']:
            o = DES3.new(pwd, mode=2)
        elif enc in ['RSA', 'RSA']:
            # Using Blowfish encryption for RSA.
            o = Blowfish.new(pwd, mode=3)
        elif not enc or enc in ['None', 'None']:
            o = None
        else:
            raise Exception('Invalid encryption mode "%s" !' % enc)
        #
        # Encryption operation.
        if o:
            pad_len = 16 - (len(txt) % 16)
            padding = (chr(pad_len) * pad_len)
            txt = o.encrypt(txt + padding)
        #
        # Codec operation.
        if post in ['Base64 Codec', 'Base64 Codec']:
            if tags:
                txt = '<#>%s:%s:%s<#>%s' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_base64(txt).decode())
            else:
                txt = ba.b2a_base64(txt).decode()
        elif post in ['Base32 Codec', 'Base32 Codec']:
            if tags:
                txt = '<#>%s:%s:%s<#>%s' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), base64.b32encode(txt).decode())
            else:
                txt = base64.b32encode(txt).decode()
        elif post in ['HEX Codec', 'HEX Codec']:
            if tags:
                txt = '<#>%s:%s:%s<#>%s' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), ba.b2a_hex(txt).decode())
            else:
                txt = ba.b2a_hex(txt).decode()
        elif post in ['Quopri Codec', 'Quopri Codec']:
            if tags:
                txt = '<#>%s:%s:%s<#>%s' % (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post].replace(' Codec',''), \
                    ba.b2a_qp(txt, quotetabs=True, header=True).decode())
            else:
                txt = ba.b2a_qp(txt, quotetabs=True, header=True).decode()
        elif post in ['Json', 'Json']:
            if tags:
                # Format : {"pre": "AAA", "enc": "BBB", "post": "CCC", "data": "Blah blah blah"}
                txt = '{"pre": "%s", "enc": "%s", "post": "%s", "data": "%s"}' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], ba.b2a_base64(txt).rstrip().decode())
            else:
                txt = json.dumps({'data':ba.b2a_base64(txt).rstrip().decode()})
        elif post in ['XML', 'XML']:
            if tags:
                # Format : <root><pre>AAA</pre> <enc>BBB</enc> <post>CCC</post> <data>Blah blah blah</data></root>
                txt = '<root>\n<pre>%s</pre><enc>%s</enc><post>%s</post>\n<data>%s</data>\n</root>' % \
                    (SCRAMBLE_D[pre], ENC[enc], ENCODE_D[post], ba.b2a_base64(txt).rstrip().decode())
            else:
                txt = '<root>\n<data>%s</data>\n</root>' % ba.b2a_base64(txt).rstrip().decode()
        else:
            raise Exception('Invalid codec "%s" !' % post)
        #
        # The final text must be String, to be used in GUI
        return txt
        #

    def decrypt(self, txt, pre, enc, post, pwd):
        #
        if type(txt) != type('') and type(txt) != type(u''):
            raise TypeError('Invalid data type for decryption: "%s" !' % str(type(txt)))
        #
        if not (pre and enc and post):
            self.guess_pre_enc_post(txt)

            pre = self.pre
            enc = self.enc
            post = self.post

            if '{' in txt and '}' in txt and '"data":' in txt:
                temp = json.loads(txt.decode())
                txt = temp['data'].encode()
                del temp
            elif '<data>' in txt and '</data>' in txt:
                txt = re.search('<data>(.+)</data>', txt, re.S).group(1).encode()
            else:
                txt = re.sub(NO_TAGS, '', txt)

        else:
            # If Json.
            if '{' in txt and '}' in txt and '"data":' in txt:
                pre = 'Json'
                temp = json.loads(txt.decode())
                txt = temp['data'].encode()

            # If XML.
            elif '<data>' in txt and '</data>' in txt:
                pre = 'XML'
                txt = re.search('<data>(.+)</data>', txt, re.S).group(1).encode()

            else:
                txt = re.sub(NO_TAGS, '', txt)
        #
        # Check RSA key path.
        if enc == 'RSA' and not os.path.exists(self.rsa_path):
            print('RSA decryption must specify a valid path !')
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
            try: txt = ba.a2b_qp(txt, header=True)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Json' or pre == ENCODE_D['Json']:
            try: txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'XML':
            try: txt = ba.a2b_base64(txt)
            except: self.__error(1, pre, enc, post) ; return
        else:
            raise Exception('Invalid codec "%s" !' % pre)
        #
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
            # Using Blowfish decryption for RSA.
            o = Blowfish.new(pwd, mode=3)
        elif not enc or enc == 'None':
            o = None
        else:
            raise Exception('Invalid decrypt "%s" !' % enc)
        #
        # Decryption operation.
        if o:
            try:
                temp = o.decrypt(txt)
                pad_len = ord(temp[-1])
                txt = temp[:-pad_len]
                del temp
            except: self.__error(2, pre, enc, post) ; return
        #
        # Un-scramble operation.
        if not post or post == 'N' or post == 'None':
            pass
        elif post == 'ZLIB' or post == SCRAMBLE_D['ZLIB']:
            try: txt = zlib.decompress(txt)
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'BZ2' or post == SCRAMBLE_D['BZ2']:
            try: txt = bz2.decompress(txt)
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'ROT13' or post == SCRAMBLE_D['ROT13']:
            txt = string.translate(txt, ROT)
        else:
            raise Exception('Invalid scramble "%s" !' % post)
        #
        return txt
        #

    def toImage(self, txt, pre, enc, post, pwd, path, encrypt=True):
        '''
        Any information, text and/or files, can be encoded inside a little PNG image. \n\
        Depending on how you encode the crypted data, images come in 3 flavors: HEX, Base32 and Base64. \n\
        Normally each letter can be encoded inside a color value from 1 to 255,
        and 4 colors become one RGBA pixel. \n\
        HEX encoding is `high density`. Two letters are transformed into a color from 1 to 255,
        so one pixel consists of 8 letters, instead of 4 letters.
        '''

        if not pre: pre = 'None'
        if not enc: enc = 'None'
        if post not in ('HEX Codec', 'Base32 Codec', 'Base64 Codec'):
            print('Encoding must be HEX, Base32, or Base64! Exiting!')
            return

        # Input can be string, or file. If's file, read it.
        if str(type(txt)) == "<type 'file'>":
            txt.seek(0)
            txt = txt.read()

        # All text must be reversed, to pop from the end of the characters list.
        if encrypt: # If text MUST be encrypted first, encrypt without pre/enc/post tags.
            val = self.encrypt(txt, pre, enc, post, pwd, False)[::-1]
            if not val:
                return
        else: # Else, the text is already encrypted.
            # Strip pre/enc/post tags.
            txt = re.sub(NO_TAGS, '', txt)
            # All information is reversed, because it's faster to just Pop from the end of a list,
            # Rather then using Pop(0), from the beggining of a list.
            # So the "first pixel" will be added at the end, but will be fetched first,
            # When creating the final image.
            val = txt[::-1]
            del txt

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
            second_pixel = struct.pack('BB', int(blank/255), (blank%256)).encode('hex')
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

        edge = int(edge)
        if not Image:
            im = QtGui.QImage(edge, edge, QtGui.QImage.Format_ARGB32)
            _pix = im.setPixel
            _rgba = QtGui.qRgba
        else:
            im = Image.new('RGBA', (edge, edge))
            _pix = im.load()
        _int = int
        _ord = ord

        # HEX codec.
        if post == 'HEX Codec':
            for i in range(edge):
                for j in range(edge):
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
                        _a = _int(list_val.pop(), 16)
                    #
                    if not Image:
                        _pix(j, i, _rgba(_r, _g, _b, _a))
                    else:
                        _pix[j, i] = (_r, _g, _b, _a)
                    #

        # Base 64 and Base 32.
        else:
            for i in range(edge):
                for j in range(edge):
                    #
                    if blank:
                        blank -= 1
                        # Put one #FFFFFFFF, completely white pixel.
                        if not Image:
                            _pix(j, i, 4294967295)
                        else:
                            _pix[j, i] = (255,255,255,255)

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

                    if not Image:
                        _pix(j, i, _rgba(_r, _g, _b, _a))
                    else:
                        _pix[j, i] = (_r, _g, _b, _a)
                    #

        #
        try:
            im.save(path, 'PNG') #, -1)
        except:
            print('Cannot save PNG file "%s" !' % path)
        #

    def fromImage(self, pwd, path, decrypt=True):
        #
        if not os.path.isfile(path):
            print('Cannot find file "%s" !' % path)
            return

        try:
            if not Image:
                im = QtGui.QImage()
                im.load(path, 'PNG')
                W = im.width()
                H = im.height()
                _r = QtGui.qRed
                _g = QtGui.qGreen
                _b = QtGui.qBlue
                _a = QtGui.qAlpha
                _pix = im.pixel

            else:
                im = Image.open(path, 'r')
                W = im.size[0] # Width
                H = im.size[1] # Height
                _pix = im.load()

        except:
            print('Image "%s" is not a valid RGBA PNG !' % path)
            return

        fp_val = 0
        list_val = []

        # Calculate First Pixel.
        for i in range(W):
            for j in range(H):
                #
                if fp_val:
                    break

                if not Image:
                    #
                    pix1 = _pix(j, i)
                    # For QtColor
                    if pix1 != 4294967295: # Color #FFFFFFFF, completely white pixel.
                        fp_val = [_r(pix1), _g(pix1), _b(pix1), _a(pix1)]
                        break
                    #
                else:
                    #
                    pix1 = _pix[j, i]
                    # For PIL Image
                    if pix1 != (255,255,255,255):
                        fp_val = pix1
                        break
                    #

        # Calculate the colors of first pixel.
        # For HEX: Red+Green represents pre/enc/post information and Blue+Alpha value represents nr of valid characters.
        # For Base64/ Base32, first pixel represents only the Pre/ Enc/ Post information.
        first_pixel_hex = struct.pack('BB', fp_val[0], fp_val[1]).encode('hex')
        blank = int(struct.pack('BB', fp_val[2], fp_val[3]).encode('hex'), 16)
        first_pixel_base = [unichr(fp_val[0]), unichr(fp_val[1]), unichr(fp_val[2]), unichr(fp_val[3])]

        # Reverse number dictionaries.
        reverse_s = dict(zip(SCRAMBLE_NR.values(), SCRAMBLE_NR.keys()))
        reverse_ey = dict(zip(ENCRYPT_NR.values(), ENCRYPT_NR.keys()))
        reverse_ed = dict(zip(ENCODE_NR.values(), ENCODE_NR.keys()))

        if first_pixel_hex[0] == '0' and first_pixel_base[0] != '0':
            post = reverse_s[first_pixel_hex[1]]
            enc = reverse_ey[first_pixel_hex[2]]
            pre = reverse_ed[first_pixel_hex[3]]
        else:
            post = reverse_s[first_pixel_base[1]]
            enc = reverse_ey[first_pixel_base[2]]
            pre = reverse_ed[first_pixel_base[3]]

        # Save Pre/ Enc/ Post information for GUI.
        self.pre = pre
        self.enc = enc
        self.post = post

        # For HEX and PyQt.
        if pre == 'HEX Codec' and not Image:
            for i in range(W):
                for j in range(H):
                    #
                    rgba = _pix(j, i)
                    #
                    # For each channel in current pixel.
                    for v in [_r(rgba), _g(rgba), _b(rgba), _a(rgba)]:
                        # This is much faster than struct.pack('B',v).encode('hex')
                        # I need 2 characters; in HEX 16=>10; less than 16 must have 0 in front of it.
                        if v < 16:
                            list_val.append('0'+hex(v)[-1])
                        else:
                            list_val.append(hex(v)[-2:])
                    #

        # For HEX and PIL Image.
        elif pre == 'HEX Codec':
            for i in range(W):
                for j in range(H):
                    #
                    rgba = _pix[j, i]
                    #
                    # For each channel in current pixel.
                    for v in rgba:
                        # I need 2 characters; in HEX 16=>10; less than 16 must have 0 in front of it.
                        if v < 16:
                            list_val.append('0'+hex(v)[-1])
                        else:
                            list_val.append(hex(v)[-2:])
                    #

        # For the rest, with PyQt.
        elif not Image:
            for i in range(W):
                for j in range(H):
                    #
                    rgba = _pix(j, i)
                    #
                    # For each channel in current pixel.
                    for v in [_r(rgba), _g(rgba), _b(rgba), _a(rgba)]:
                        if v and v != 255:
                            list_val.append(unichr(v))
                        # If this color is 0 or 255, the rest of the pixel is blank.
                        else:
                            break
                    #

        # For the rest, with PIL Image.
        else:
            for i in range(W):
                for j in range(H):
                    #
                    rgba = _pix[j, i]
                    #
                    # For each channel in current pixel.
                    for v in rgba:
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
        #ff.close() ; del ff, fp_val

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

        # For PNG files.
        if ext=='.png':
            return self.fromImage(pwd, fpath, decrypt)

        txt = open(fpath, 'rb').read()

        # For the rest of the files.
        if decrypt:
            val = self.decrypt(txt, pre, enc, post, pwd)
            if not val:
                print(self.error)
            else:
                return val

        # Else, don't decrypt.
        else:
            self.guess_pre_enc_post(txt)
            return txt
        #


# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----
#       Scrambled-Egg  Encryption  CMD
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

def commandLine():

    import optparse
    usage = """
Encryption: %prog --input in_file [--output out_file] -p password --pre PRE --enc ENC --post POST
or
Decryption: %prog --input in_file [--output out_file] -p password --decrypt true"""
    version="%prog v1.0"
    description = '''Scrambled-Egg v1.0 command line.
Compress, encrypt and encode your file in command line.
* pre  - can be one of the values: ROT13, ZLIB, BZ2, None ;
* enc  - can be one of : AES, Blowfish, ARC2, CAST, DES3, RSA ;
* post - can be one of : Base64, Base32, HEX, Json, XML.
'''

    parser = optparse.OptionParser(usage=usage, version=version, description=description)
    parser.add_option("-i", "--input",  action="store", help="input file path")
    parser.add_option("-o", "--output", action="store", help="output file path")
    parser.add_option("-p", "--pwd",    action="store", help="password used for encryption")
    parser.add_option("--decrypt",      action="store", help="decrypt operation (default=False)")
    parser.add_option("--pre",          action="store", help="pre operation     (compress, default=None)")
    parser.add_option("-e", "--enc",    action="store", help="encryption operation (default=AES)")
    parser.add_option("--post",         action="store", help="post operation    (encode, default=Base64)")
    (options, args) = parser.parse_args()

    if not options.output:
        options.output = 'output.dat'

    if not options.enc and not options.decrypt:
        options.enc = 'AES'
    elif options.decrypt:
        options.enc = 'X'

    if not options.pre and not options.decrypt:
        options.pre = 'None'
    elif options.decrypt:
        options.pre = 'X'

    if not options.post and not options.decrypt:
        options.post = 'Base64'
    elif options.decrypt:
        options.post = 'X'

    if not options.input:
        print('Must specify an input file ! Exiting !')
        return 1

    if not os.path.exists(options.input):
        print('The file `%s` doesn\'t exist ! Exiting !' % options.input)
        return 1

    if not options.pwd:
        print('Must specify a password ! Exiting !')
        return 1

    pre =  {'NONE':'None', 'ROT13':'ROT13', 'ZLIB':'ZLIB', 'BZ2':'BZ2', 'X':None}
    enc =  {'AES':'AES', 'BLOWFISH':'Blowfish', 'ARC2':'ARC2', 'CAST':'CAST', 'DES3':'DES3', 'RSA':'RSA', 'X':None}
    post = {'BASE64':'Base64 Codec', 'BASE32':'Base32 Codec', 'HEX':'HEX Codec', 'JSON':'Json', 'XML':'XML', 'X':None}

    if options.enc.upper() not in enc:
        print('Value `%s` is an invalid encryption operation ! Exiting !' % options.enc)
        return 1

    if options.pre.upper() not in pre:
        print('Value `%s` is an invalid pre operation ! Exiting !' % options.pre)
        return 1

    if options.post.upper() not in post:
        print('Value `%s` is an invalid post operation ! Exiting !' % options.post)
        return 1

    if options.decrypt:
        SE = ScrambledEgg()
        print('Decrypting from `%s` to `%s`...' % (options.input, options.output))
        val = SE.decrypt(open(options.input, 'rb').read(),
            pre[options.pre.upper()], enc[options.enc.upper()], post[options.post.upper()],
            pwd=options.pwd)
        open(options.output, 'wb').write(val)

    else:
        SE = ScrambledEgg()
        print('Encrypting from `%s` to `%s`...' % (options.input, options.output))
        val = SE.encrypt(open(options.input, 'rb').read(),
            pre[options.pre.upper()], enc[options.enc.upper()], post[options.post.upper()],
            options.pwd, tags=True)
        open(options.output, 'wb').write(val)

#

if __name__ == '__main__':

    if sys.argv[1:]:
        exit(commandLine())

#
# Eof()
#
