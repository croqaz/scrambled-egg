#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os, sys
import subprocess
import re, math
import string
import struct
import urllib
import base64
import json
import bz2, zlib
import tarfile

import binascii as ba
from collections import OrderedDict
from cStringIO import StringIO
from Padding import appendPadding, removePadding
from pbkdf2 import PBKDF2

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

try: import Image
except: Image = None

# TODO for next versions:
# Command line to encrypt/ decrypt.
# Daemon to watch for files in folders and encrypt them, maybe?

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
C = {} # Config.
D = {} # Themes.
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
        hash_key = PBKDF2(passphrase=pwd, salt='scregg', iterations=1024)

        # The password for encryption/ decryption.
        # This is very strong, binary data!
        return hash_key.read(key_size)
        #

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
            temp = appendPadding(txt, blocksize=16)
            txt = o.encrypt(temp)
            del temp
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
            # Trying to identify and/or delete pre/enc/post tags.
            #try:
            re_groups = re.search(NO_TAGS, txt).groups()
            tags = findg(re_groups)

            # If Json.
            if '{' in txt and '}' in txt and '"data":' in txt:
                pre = 'Json'
                temp = json.loads(txt.decode())
                enc = temp.get('enc').encode()
                post = temp.get('pre').encode()
                txt = temp['data'].encode()

            # If XML.
            elif '<data>' in txt and '</data>' in txt:
                pre = 'XML'
                enc = re.search('<enc>([0-9a-zA-Z ]{1,3})</enc>', tags).group(1)
                post = re.search('<pre>([0-9a-zA-Z ]{1,3})</pre>', tags).group(1)
                txt = re.search('<data>(.+)</data>', txt, re.S).group(1)

            else:
                pre = tags.split(':')[2]
                enc = tags.split(':')[1]
                post = tags.split(':')[0]
                txt = re.sub(NO_TAGS, '', txt)

            pre = self.pre = pre.decode()
            enc = self.enc = enc.decode()
            post = self.post = post.decode()

            #except:
            #    print('Cannot decrypt, caught error with', pre, enc, post, '!')

        else:
            # If Json.
            if '{' in txt and '}' in txt and '"data":' in txt:
                pre = 'Json'
                temp = json.loads(txt.decode())
                txt = temp['data'].encode()

            # If XML.
            elif '<data>' in txt and '</data>' in txt:
                pre = 'XML'
                txt = re.search('<data>(.+)</data>', txt, re.S).group(1)

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
                txt = removePadding(temp, 16)
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


# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----
#       GUI  Container  Widget
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

class ContainerWidget(QtGui.QWidget):

    def __init__(self, parent):
        '''
        Main container. It's not transparent. \n\
        I must use this, to accept file drops.
        '''
        super(ContainerWidget, self).__init__(parent)
        self.mMoving = False
        self.setMouseTracking(False)
        self.setSizePolicy(QtGui.QSizePolicy(QtGui.QSizePolicy.Maximum, QtGui.QSizePolicy.Maximum))

    def mousePressEvent(self, event):
        if(event.button() == QtCore.Qt.LeftButton):
            self.mMoving = True
            self.mOffset = event.pos()

    def mouseMoveEvent(self, event):
        if(self.mMoving):
            self.parentWidget().move(event.globalPos() - self.mOffset)

    def mouseReleaseEvent(self, event):
        if(event.button() == QtCore.Qt.LeftButton):
            self.mMoving = False


# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----
#       MAIN  Scrambled-Egg  Window
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

class Window(QtGui.QMainWindow):

    def __init__(self):
        '''
        Main window class.
        It's frameless and transparent.
        '''
        super(Window, self).__init__(None, QtCore.Qt.FramelessWindowHint)
        QtGui.QApplication.setStyle(QtGui.QStyleFactory.create('CleanLooks'))
        QtGui.QApplication.setPalette(QtGui.QApplication.style().standardPalette())

        icon_path = os.path.split(os.path.abspath(__file__))[0] + '/config/icon.ico'
        self.setWindowIcon(QtGui.QIcon(icon_path))
        self.resize(C['W_WIDTH'], C['W_HEIGHT'])
        self.setMaximumHeight(C['W_MAX_HEIGHT'])
        self.setStyleSheet(D['STYLE_MAIN'])
        self.setWindowTitle('Scrambled Egg %s :: Live Crypt' % __version__)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        #self.setWindowOpacity(0.9)
        self.setAcceptDrops(True)

        self.SE = ScrambledEgg()

        self.centralWidget = ContainerWidget(self) # Central Widget.
        self.setCentralWidget(self.centralWidget)
        self.container = QtGui.QWidget(self.centralWidget) # Container Widget.
        self.container.setObjectName('Container')
        self.container.setStyleSheet(D['STYLE_CONTAINER'])

        self.textBar = QtGui.QLabel(self) # Top text bar.
        self.layout = QtGui.QGridLayout(self.centralWidget) # Main Layout.
        self.centralWidget.setLayout(self.layout)

        self.leftText = QtGui.QTextEdit('', self.centralWidget)        # To write clean text.
        self.rightText = QtGui.QPlainTextEdit('' , self.centralWidget) # To view encrypted text.

        self.buttonCryptMode = QtGui.QPushButton(self.centralWidget)
        self.buttonDecryptMode = QtGui.QPushButton(self.centralWidget)
        self.buttonBrowseRSAL = QtGui.QPushButton('Browse', self.centralWidget)
        self.buttonBrowseRSAR = QtGui.QPushButton('Browse', self.centralWidget)

        self.preProcess = QtGui.QComboBox(self.centralWidget)    # Left side.
        self.comboCrypt = QtGui.QComboBox(self.centralWidget)    # Left side.
        self.postProcess = QtGui.QComboBox(self.centralWidget)   # Left side.
        self.linePasswordL = QtGui.QLineEdit(self.centralWidget) # Left password line.
        self.lineRSAPathL = QtGui.QLineEdit(self.centralWidget)  # Left RSA Path line.
        self.checkPwdL = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Left side.
        self.nrLettersL = QtGui.QLabel('', self.centralWidget)   # Left side.
        self.setFormatting = QtGui.QCheckBox('Formatted text', self.centralWidget) # Left side.
        self.showHTML = QtGui.QCheckBox('Show HTML', self.centralWidget) # Left side.
        self.setTags = QtGui.QCheckBox('No tags', self.centralWidget)    # Left side.

        self.preDecrypt = QtGui.QComboBox(self.centralWidget)    # Right side.
        self.comboDecrypt = QtGui.QComboBox(self.centralWidget)  # Right side.
        self.postDecrypt = QtGui.QComboBox(self.centralWidget)   # Right side.
        self.linePasswordR = QtGui.QLineEdit(self.centralWidget) # Right password line.
        self.lineRSAPathR = QtGui.QLineEdit(self.centralWidget)  # Right RSA Path line.
        self.checkPwdR = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Right side.
        self.nrLettersR = QtGui.QLabel('', self.centralWidget)   # Right side.
        self.loadFile = QtGui.QPushButton('Import', self.centralWidget)   # Right side.
        self.saveFile = QtGui.QPushButton('Export', self.centralWidget)   # Right side.
        self.helpButton = QtGui.QPushButton('Help !', self.centralWidget) # Right side.

        self.minButton = QtGui.QPushButton(D['MIN_BTN_TXT'], self.centralWidget)
        self.closeButton = QtGui.QPushButton(D['CLOSE_BTN_TXT'], self.centralWidget)
        self.micLayout = QtGui.QHBoxLayout()
        self.micLayout.addWidget(self.minButton)
        self.micLayout.addWidget(self.closeButton)

        # Row, Col, rowSpan, colSpan
        self.layout.addWidget(self.container,           0, 0, 12, 15)
        self.layout.addWidget(self.textBar,             1, 1, 3, 8)
        self.layout.addLayout(self.micLayout,           1, 10+C['MIC_BTNS_POS'], 1, C['MIC_BTNS_SPAN'])
        self.layout.addItem(QtGui.QSpacerItem(1, 8),    3, 1, 1, 1)

        self.layout.addWidget(self.buttonCryptMode,     4, 2, 1, 5)
        self.layout.addWidget(self.buttonDecryptMode,   4, 7, 1, 5)

        self.layout.addWidget(self.preProcess,          5, 2, 1, 1)
        self.layout.addWidget(self.comboCrypt,          5, 3, 1, 1)
        self.layout.addWidget(self.postProcess,         5, 4, 1, 1)
        self.layout.addWidget(self.preDecrypt,          5, 7, 1, 1)
        self.layout.addWidget(self.comboDecrypt,        5, 8, 1, 1)
        self.layout.addWidget(self.postDecrypt,         5, 9, 1, 1)

        self.layout.addWidget(self.linePasswordL,       6, 2, 1, 4)
        self.layout.addWidget(self.linePasswordR,       6, 7, 1, 4)
        self.layout.addWidget(self.checkPwdL,           6, 6, 1, 1)
        self.layout.addWidget(self.checkPwdR,           6, 11, 1, 1)

        self.layout.addWidget(self.lineRSAPathL,        7, 2, 1, 4)
        self.layout.addWidget(self.lineRSAPathR,        7, 7, 1, 4)
        self.layout.addWidget(self.buttonBrowseRSAL,    7, 6, 1, 1)
        self.layout.addWidget(self.buttonBrowseRSAR,    7, 11, 1, 1)

        self.layout.addWidget(self.leftText,            8, 2, 2, 5)
        self.layout.addWidget(self.rightText,           8, 7, 2, 5)

        self.layout.addWidget(self.setFormatting,       10, 2, 1, 1)
        self.layout.addWidget(self.showHTML,            10, 3, 1, 1)
        self.layout.addWidget(self.setTags,             10, 4, 1, 1)
        self.layout.addWidget(self.loadFile,            10, 7, 1, 1)
        self.layout.addWidget(self.saveFile,            10, 8, 1, 1)
        self.layout.addWidget(self.helpButton,          10, 9, 1, 1)

        self.layout.addWidget(self.nrLettersL,          10, 6, 1, 1)
        self.layout.addWidget(self.nrLettersR,          10, 11, 1, 1)

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
        self.buttonCryptMode.setStyleSheet(D['STYLE_BUTTON'])
        self.buttonDecryptMode.setCheckable(True)
        self.buttonDecryptMode.setToolTip('Switch to Decryption mode')
        self.buttonDecryptMode.setStyleSheet(D['STYLE_BUTTON'])

        self.helpButton.setStyleSheet(D['STYLE_HELP_BUTTON'])
        self.minButton.setMaximumWidth(25)
        self.minButton.setMaximumHeight(25)
        self.minButton.setStyleSheet(D['STYLE_MIN_BUTTON'])
        self.closeButton.setMaximumWidth(25)
        self.closeButton.setMaximumHeight(25)
        self.closeButton.setStyleSheet(D['STYLE_CLOSE_BUTTON'])

        # Some styles.
        self.loadFile.setStyleSheet(D['STYLE_BUTTON'])
        self.saveFile.setStyleSheet(D['STYLE_BUTTON'])
        self.leftText.setStyleSheet(D['STYLE_L_TEXTEDIT'])
        self.rightText.setStyleSheet(D['STYLE_R_TEXTEDIT'])
        self.leftText.setSizePolicy(QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding))
        self.rightText.setSizePolicy(QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding))

        # Password fields.
        self.linePasswordL.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordL.setToolTip('Password used for encrypting the text')
        self.linePasswordL.setMaxLength(99)
        self.linePasswordL.setStyleSheet(D['STYLE_LINEEDIT'])
        self.checkPwdL.setTristate(False)
        self.checkPwdL.setStyleSheet(D['STYLE_CHECKBOX'])
        self.linePasswordR.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordR.setToolTip('Password used for decrypting the text')
        self.linePasswordR.setMaxLength(99)
        self.linePasswordR.setDisabled(True)
        self.linePasswordR.setStyleSheet(D['STYLE_LINEEDIT'])
        self.checkPwdR.setTristate(False)
        self.checkPwdR.setStyleSheet(D['STYLE_CHECKBOX'])

        # RSA Path.
        self.lineRSAPathL.setStyleSheet(D['STYLE_LINEEDIT'])
        self.lineRSAPathL.setToolTip('RSA Encryption requires both a password and the path to a public/ private RSA key')
        self.lineRSAPathL.hide()
        self.lineRSAPathR.setStyleSheet(D['STYLE_LINEEDIT'])
        self.lineRSAPathR.setToolTip('RSA Decryption requires both a password and the path to a public/ private RSA key')
        self.lineRSAPathR.hide()
        self.lineRSAPathR.setDisabled(True)

        self.buttonBrowseRSAL.setStyleSheet(D['STYLE_BUTTON'])
        self.buttonBrowseRSAL.hide()
        self.buttonBrowseRSAL.setMaximumWidth(60)
        self.buttonBrowseRSAR.setStyleSheet(D['STYLE_BUTTON'])
        self.buttonBrowseRSAR.hide()
        self.buttonBrowseRSAR.setMaximumWidth(60)
        self.buttonBrowseRSAR.setDisabled(True)

        # Formatted text.
        self.setFormatting.setTristate(False)
        self.setFormatting.setToolTip('Encrypt this text as HTML')
        self.setFormatting.setStyleSheet(D['STYLE_CHECKBOX'])
        self.setTags.setTristate(False)
        self.setTags.setToolTip('Strip pre/enc/post tags')
        self.setTags.setStyleSheet(D['STYLE_CHECKBOX'])
        self.showHTML.setTristate(False)
        self.showHTML.setToolTip('Toogle view HTML source behind the formatted text')
        self.showHTML.setStyleSheet(D['STYLE_CHECKBOX'])

        # All combo boxes.
        MIN = 120
        self.preProcess.setMinimumWidth(MIN)
        self.preProcess.setStyleSheet(D['STYLE_COMBOBOX'])
        self.comboCrypt.setMinimumWidth(MIN)
        self.comboCrypt.setStyleSheet(D['STYLE_COMBOBOX'])
        self.postProcess.setMinimumWidth(MIN)
        self.postProcess.setStyleSheet(D['STYLE_COMBOBOX'])
        self.preDecrypt.setMinimumWidth(MIN)
        self.preDecrypt.setStyleSheet(D['STYLE_COMBOBOX'])
        self.comboDecrypt.setMinimumWidth(MIN)
        self.comboDecrypt.setStyleSheet(D['STYLE_COMBOBOX'])
        self.postDecrypt.setMinimumWidth(MIN)
        self.postDecrypt.setStyleSheet(D['STYLE_COMBOBOX'])

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
        self.buttonBrowseRSAL.clicked.connect(self.browseRSAkey)
        self.buttonBrowseRSAR.clicked.connect(self.browseRSAkey)
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
        self.minButton.clicked.connect(lambda: self.setWindowState(QtCore.Qt.WindowMinimized))
        self.closeButton.clicked.connect(lambda: self.close())
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
                #
                f_name = urllib.unquote(url)
                # Ignore windows shortcuts. They are ugly :)
                if os.path.splitext(f_name)[1].lower() == '.lnk':
                    continue
                o = urllib.urlopen(url)
                sz = os.fstat(o.fileno())[6]
                t = tarfile.TarInfo(os.path.split(f_name)[1])
                t.size = sz
                #self.attach.addFile(t, o) #?
                #

        print('I should encrypt on DROP!')
        #

    def browseRSAkey(self):
        #
        f = QtGui.QFileDialog()
        path = f.getOpenFileName(self, 'Path to RSA public or private key', os.getcwd(), 'All files (*.*)')
        if not path:
            return
        #
        self.SE.rsa_path = path
        self.lineRSAPathL.setText(path)
        self.lineRSAPathR.setText(path)
        #

    def onCryptMode(self):
        #
        self.buttonCryptMode.setChecked(True)
        self.buttonCryptMode.setText('Encrypt Mode is Enabled')
        self.buttonDecryptMode.setChecked(False)
        self.buttonDecryptMode.setText('Decrypt Mode')
        #
        self.linePasswordL.setDisabled(False)
        self.lineRSAPathL.setDisabled(False)
        self.buttonBrowseRSAL.setDisabled(False)
        self.leftText.setDisabled(False)
        #
        self.linePasswordR.setDisabled(True)
        self.lineRSAPathR.setDisabled(True)
        self.buttonBrowseRSAR.setDisabled(True)
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
        self.lineRSAPathL.setDisabled(True)
        self.buttonBrowseRSAL.setDisabled(True)
        self.leftText.setDisabled(True)
        #
        self.linePasswordR.setDisabled(False)
        self.lineRSAPathR.setDisabled(False)
        self.buttonBrowseRSAR.setDisabled(False)
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
        def spacerepl(matchobj):
            return matchobj.group(0).replace(' ', '&nbsp;')

        txt = re.sub('>([^<>]+)<(?!/style>)', spacerepl, txt)
        open('doc.htm', 'wb').write(txt)

        p = subprocess.Popen('tidy.exe ' + ' -config config.txt doc.htm', shell=False).wait()
        txt = []
        for line in open('doc.htm', 'rb').readlines():
            if '<title' in line:
                continue
            elif '<meta' in line:
                continue
            print line
            txt.append(line)

        txt = ''.join(txt)
        os.remove('doc.htm')

        #open('doc.htm', 'wb').write(txt)
        return txt
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
        #
        # Save all pre/enc/post operations.
        pre = self.preProcess.currentText()
        enc = self.comboCrypt.currentText()
        post = self.postProcess.currentText()
        #
        # If encryption mode is RSA, reveal key path.
        if enc=='RSA':
            self.lineRSAPathL.show()
            self.lineRSAPathR.show()
            self.buttonBrowseRSAL.show()
            self.buttonBrowseRSAR.show()
        else:
            self.lineRSAPathL.hide()
            self.lineRSAPathR.hide()
            self.buttonBrowseRSAL.hide()
            self.buttonBrowseRSAR.hide()
        #
        if not self.leftText.toPlainText():
            self.rightText.clear()
            return
        #
        pwd = self.linePasswordL.text().encode()
        tags = not self.setTags.isChecked()
        #
        if self.setFormatting.isChecked() and not self.showHTML.isChecked():
            # HTML string.
            txt = self.leftText.toHtml().encode()
            # Cleanup HTML string.
            txt = self.cleanupHtml(txt)
        else:
            txt = self.leftText.toPlainText().encode()
        #
        # Setup default (no error) status.
        if self.buttonCryptMode.isChecked():
            self.textBar.setStyleSheet(D['TXT_BAR_OK'])
            self.textBar.setText('  Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
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
            self.textBar.setStyleSheet(D['TXT_BAR_BAD'])
            self.textBar.setText(self.SE.error)
        #

    def onRightTextChanged(self):
        #
        if not self.buttonDecryptMode.isChecked():
            return
        #
        txt = self.rightText.toPlainText().encode()
        #
        try:
            re_groups = re.search(NO_TAGS, txt).groups()
            tags = findg(re_groups)

            # If Json.
            if tags.startswith('"pre"'):
                pre = 'Json'
                enc = re.search('"enc":"([0-9a-zA-Z ]{1,3})"', tags).group(1)
                post = re.search('"pre":"([0-9a-zA-Z ]{1,3})"', tags).group(1)
            # If XML.
            elif tags.startswith('<pre>'):
                pre = 'XML'
                enc = re.search('<enc>([0-9a-zA-Z ]{1,3})</enc>', tags).group(1)
                post = re.search('<pre>([0-9a-zA-Z ]{1,3})</pre>', tags).group(1)
            else:
                pre=None ; enc=None ; post=None

            # Identify the rest.
            if not pre:
                pre = tags.split(':')[2]
            if not enc:
                enc = tags.split(':')[1]
            if not post:
                post = tags.split(':')[0]

            pre = pre.decode()
            enc = enc.decode()
            post = post.decode()

            self.postDecrypt.setCurrentIndex( self.postDecrypt.findText(post, QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.comboDecrypt.setCurrentIndex( self.comboDecrypt.findText(enc, QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.preDecrypt.setCurrentIndex( self.preDecrypt.findText(pre, QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
        except:
            pass
        #
        # This must be right here.
        pre = self.preDecrypt.currentText()
        enc = self.comboDecrypt.currentText()
        post = self.postDecrypt.currentText()
        pwd = self.linePasswordR.text().encode()
        #
        # If encryption mode is RSA, reveal key path.
        if enc=='RSA':
            self.lineRSAPathL.show()
            self.lineRSAPathR.show()
            self.buttonBrowseRSAL.show()
            self.buttonBrowseRSAR.show()
        else:
            self.lineRSAPathL.hide()
            self.lineRSAPathR.hide()
            self.buttonBrowseRSAL.hide()
            self.buttonBrowseRSAR.hide()
        #
        if not txt:
            self.leftText.clear()
            return
        #
        if self.buttonDecryptMode.isChecked():
            self.textBar.setStyleSheet(D['TXT_BAR_OK'])
            self.textBar.setText('  Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
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
            self.leftText.setHtml(final.decode())
            self.nrLettersL.setText('Dec: %i' % len(final))
            self.nrLettersR.setText('Enc: %i' % len(txt))
        else:
            self.leftText.clear()
            self.textBar.setStyleSheet(D['TXT_BAR_BAD'])
            self.textBar.setText(self.SE.error)
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
        elif post=='XML':
            path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'XML Files (*.xml)')
            ext = '.xml'
        elif post=='Json':
            path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'Json Files (*.json)')
            ext = '.json'
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
        QtGui.QMessageBox.about(self.centralWidget, 'Scrambled Egg %s Help' % __version__,
            '<br><b>Copyright (C) 2010-2011</b> : Cristi Constantin. All rights reserved.<br>'
            '<b>Website</b> : http://scrambled-egg.googlecode.com/<br><br>'
            'Scrambled-Egg is a software designed for encrypting your sensitive data.<br>'
            'This is done in <font color="blue"><b>3 steps</b></font> : <i>pre encryption</i>, <i>encryption</i>, and <i>post encryption</i>.<br>'
            'The input data can be : plain text, formatted text, or a binary file.<br><br>'
            '<font color="blue"><b>Step 1</b></font> can compress your data using <b>ZLIB</b>, or <b>BZ2</b>. This step is optional.<br>'
            '<font color="blue"><b>Step 2</b></font> is the real encryption, for example with <b>AES</b>, or <b>Blowfish</b>. '
            'The password is used only in this step. '
            'For <b>RSA</b> encryption, along with the password, you have to type the path to the public or private RSA key.<br>'
            '<font color="blue"><b>Step 3</b></font> will encode your data. This step is required, the rest are optional. '
            'There are a lot of encodings available, for example <b>Base64</b>, or <b>HEX</b>.<br><br>'
            'This FREE program is distributed in the hope that it will be useful.<br><br>'
            'Enjoy!')
        #

#

def loadConfig():

    script_path = os.path.abspath(__file__)
    base_path = os.path.split(script_path)[0] + '/config/'
    C = {}

    if os.path.exists(base_path):
        try:
            c = open(base_path + 'config.json', 'r').read()
            C = json.loads(c)
        except:
            print('Cannot load config: `{0}` ! Using builtin config !'.format(base_path + 'config.json'))

    C['W_WIDTH'] = C.get('W_WIDTH', 800)
    C['W_HEIGHT'] = C.get('W_HEIGHT', 420)
    C['W_MAX_HEIGHT'] = C.get('W_MAX_HEIGHT', 660)
    C['THEME'] = C.get('THEME', 'default/theme.json')
    C['MIC_BTNS_POS'] = C.get('MIC_BTNS_POS', 1)
    C['MIC_BTNS_SPAN'] = C.get('MIC_BTNS_SPAN', 1)
    return C

#

def loadThemes():

    script_path = os.path.abspath(__file__)
    theme_file = os.path.split(script_path)[0] + '/config/themes/' + C['THEME']
    theme_path = os.path.split(theme_file)[0]
    D = {}

    try:
        c = open(theme_file, 'r').read()
        theme_path = theme_path.replace('\\', '/')
        c = c.replace('%HOME%', theme_path)
        D = json.loads(c)
    except:
        print('Cannot load theme: `{0}` ! Using builtin theme !'.format(theme_path))

    D['STYLE_MAIN']         = D.get('STYLE_MAIN', "QMainWindow {background:transparent;}")
    D['STYLE_CONTAINER']    = D.get('STYLE_CONTAINER',   "#ContainerWidget {background:white; border:3px solid grey; border-radius:11px;}")
    D['STYLE_BUTTON']       = D.get('STYLE_BUTTON',      "QPushButton {color:#2E2633; background-color:#E1EDB9;} QPushButton:checked {color:#555152; background-color:#F3EFEE;} QPushButton:disabled {background-color:#EFEBE7;} QPushButton::hover {color:#99173C;}")
    D['TXT_BAR_OK']         = D.get('TXT_BAR_OK',  "color:blue")
    D['TXT_BAR_BAD']        = D.get('TXT_BAR_BAD', "color:red")
    D['STYLE_HELP_BUTTON']  = D.get('STYLE_HELP_BUTTON',  D['STYLE_BUTTON'])
    D['STYLE_MIN_BUTTON']   = D.get('STYLE_MIN_BUTTON',   D['STYLE_BUTTON'])
    D['STYLE_CLOSE_BUTTON'] = D.get('STYLE_CLOSE_BUTTON', D['STYLE_BUTTON'])
    D['STYLE_LINEEDIT']     = D.get('STYLE_LINEEDIT',   "QLineEdit      {background-color:#E1EDB9; border:1px solid #A59D95; border-radius:4px;} QLineEdit:disabled      {background-color:#EFEBE7;}                QLineEdit:focus      {border:1px solid #99173C;}")
    D['STYLE_L_TEXTEDIT']   = D.get('STYLE_L_TEXTEDIT', "QTextEdit      {background-color:#E1EDB9; border:1px solid #A59D95; border-radius:4px;} QTextEdit:disabled      {color:#555152; background-color:#EFEBE7;} QTextEdit:focus      {border:1px solid #99173C;}")
    D['STYLE_R_TEXTEDIT']   = D.get('STYLE_R_TEXTEDIT', "QPlainTextEdit {background-color:#E1EDB9; border:1px solid #A59D95; border-radius:4px;} QPlainTextEdit:disabled {color:#555152; background-color:#EFEBE7;} QPlainTextEdit:focus {border:1px solid #99173C;}")
    D['STYLE_CHECKBOX']     = D.get('STYLE_CHECKBOX',   "QCheckBox {color:#2E2633; margin:0px;} QCheckBox::hover {color:#99173C; background:transparent; margin:0px;}")
    D['STYLE_COMBOBOX']     = D.get('STYLE_COMBOBOX',   "QComboBox {color:#2E2633;} QComboBox QAbstractItemView {selection-background-color:#E1EDB9;}")
    D['MIN_BTN_TXT']        = D.get('MIN_BTN_TXT', '_')
    D['CLOSE_BTN_TXT']      = D.get('CLOSE_BTN_TXT', 'X')
    return D

#

def commandLine():

    import optparse
    usage = "usage: %prog --input in_file [--output out_file] --pre PRE --enc ENC --post POST"
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
    parser.add_option("--pre",          action="store", help="pre operation    (compress, default=None)")
    parser.add_option("-e", "--enc",    action="store", help="encryption operation  (default=AES)")
    parser.add_option("--post",         action="store", help="post operation   (encode, default=Base64)")
    (options, args) = parser.parse_args()

    if not options.output:
        options.output = 'output.dat'

    if not options.enc:
        options.enc = 'AES'

    if not options.pre:
        options.pre = 'None'

    if not options.post:
        options.post = 'Base64'

    if not options.input:
        print('Must specify an input file ! Exiting !')
        return 1

    if not os.path.exists(options.input):
        print('The file `%s` doesn\'t exist ! Exiting !' % options.input)
        return 1

    if not options.pwd:
        print('Must specify a password ! Exiting !')
        return 1

    pre =  {'NONE':'None', 'ROT13':'ROT13', 'ZLIB':'ZLIB', 'BZ2':'BZ2'}
    enc =  {'AES':'AES', 'BLOWFISH':'Blowfish', 'ARC2':'ARC2', 'CAST':'CAST', 'DES3':'DES3', 'RSA':'RSA'}
    post = {'BASE64':'Base64 Codec', 'BASE32':'Base32 Codec', 'HEX':'HEX Codec', 'JSON':'Json', 'XML':'XML'}

    if options.enc.upper() not in enc:
        print('Value `%s` is an invalid encryption operation ! Exiting !' % options.enc)
        return 1

    if options.pre.upper() not in pre:
        print('Value `%s` is an invalid pre operation ! Exiting !' % options.pre)
        return 1

    if options.post.upper() not in post:
        print('Value `%s` is an invalid post operation ! Exiting !' % options.post)
        return 1

    SE = ScrambledEgg()
    val = SE.encrypt(open(options.input,'rb').read(),
        pre[options.pre.upper()], enc[options.enc.upper()], post[options.post.upper()],
        options.pwd, tags=True)
    open(options.output,'w').write(val)

#

if __name__ == '__main__':

    if sys.argv[1:]:
        exit(commandLine())

    C = loadConfig()
    D = loadThemes()
    app = QtGui.QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())

#
# Eof()
#
