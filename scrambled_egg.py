#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.blogspot.com.
# ---

import os, sys
import re, math

from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import CAST
from Crypto.Cipher import DES3

from PIL import Image

import sip
sip.setapi('QString', 2)
sip.setapi('QVariant', 2)

from PyQt4 import QtCore
from PyQt4 import QtGui


#
SCRAMBLE = {'None':'N', 'ZLIB':'ZL', 'BZ2':'BZ', 'ROT13':'R'}
ENC = {'AES':'A', 'Blowfish':'B', 'CAST':'C', 'DES3':'D', 'None':'N'}
ENCODE = {'Base64 Codec':'B', 'HEX Codec':'H', 'Quopri Codec':'Q', 'String Escape':'STR', 'UU Codec':'UU'}
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

    def encrypt(self, txt, pre, enc, post, pwd):
        #
        L = len(pwd)
        pwd += 'X' * ( (((L/16)+1)*16) - L )
        #
        if pre == 'None':
            pass
        elif pre == 'ZLIB':
            txt = txt.encode('zlib')
        elif pre == 'BZ2':
            txt = txt.encode('bz2')
        elif pre == 'ROT13':
            try: txt = txt.encode('rot13')
            except: self.__error(1, pre, enc, post, 'L')
        else:
            raise Exception('Invalid scramble !')
        #
        L = len(txt)
        txt += 'X' * ( (((L/16)+1)*16) - L )
        #
        if enc == 'AES':
            o = AES.new(pwd)
            encrypted = o.encrypt(txt)
        elif enc == 'Blowfish':
            o = Blowfish.new(pwd)
            encrypted = o.encrypt(txt)
        elif enc == 'CAST':
            o = CAST.new(pwd)
            encrypted = o.encrypt(txt)
        elif enc == 'DES3':
            o = DES3.new(pwd)
            encrypted = o.encrypt(txt)
        elif enc == 'None':
            encrypted = txt
        else:
            raise Exception('Invalid encryption mode !')
        #
        if post == 'Base64 Codec':
            final = '<#>%s:%s:%s<#>' % (SCRAMBLE[pre], ENC[enc], ENCODE[post].replace(' Codec','')) + encrypted.encode('base64')
        elif post == 'HEX Codec':
            final = '<#>%s:%s:%s<#>' % (SCRAMBLE[pre], ENC[enc], ENCODE[post].replace(' Codec','')) + encrypted.encode('hex')
        elif post == 'Quopri Codec':
            final = '<#>%s:%s:%s<#>' % (SCRAMBLE[pre], ENC[enc], ENCODE[post].replace(' Codec','')) + encrypted.encode('quopri_codec')
        elif post == 'String Escape':
            final = '<#>%s:%s:%s<#>' % (SCRAMBLE[pre], ENC[enc], ENCODE[post]) + encrypted.encode('string_escape')
        elif post == 'UU Codec':
            final = '<#>%s:%s:%s<#>' % (SCRAMBLE[pre], ENC[enc], ENCODE[post].replace(' Codec','')) + encrypted.encode('uu')
        else:
            raise Exception('Invalid codec !')
        #
        return final
        #

    def decrypt(self, txt, pre, enc, post, pwd):
        #
        if pre == 'Base64 Codec':
            try: txt = txt.decode('base64')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'HEX Codec':
            try: txt = txt.decode('hex')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'Quopri Codec':
            try: txt = txt.decode('quopri_codec')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'String Escape':
            try: txt = txt.decode('string_escape')
            except: self.__error(1, pre, enc, post) ; return
        elif pre == 'UU Codec':
            try: txt = txt.decode('uu')
            except: self.__error(1, pre, enc, post) ; return
        else:
            raise Exception('Invalid codec !')
        #
        if enc == 'AES':
            o = AES.new(pwd)
        elif enc == 'Blowfish':
            o = Blowfish.new(pwd)
        elif enc == 'CAST':
            o = CAST.new(pwd)
        elif enc == 'DES3':
            o = DES3.new(pwd)
        elif enc == 'None':
            txt = txt.rstrip('X')
        else:
            raise Exception('Invalid decrypt !')
        #
        if enc != 'None':
            try: txt = o.decrypt(txt).rstrip('X')
            except: self.__error(2, pre, enc, post) ; return
        #
        if post == 'None':
            final = txt
        elif post == 'ZLIB':
            try: final = txt.decode('zlib')
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'BZ2':
            try: final = txt.decode('bz2')
            except: self.__error(3, pre, enc, post) ; return
        elif post == 'ROT13':
            try: final = txt.decode('rot13')
            except: self.__error(3, pre, enc, post) ; return
        else:
            raise Exception('Invalid scramble !')
        #
        return final
        #

    def toImage(self, txt, pre, enc, post, pwd, path, encrypt=True):
        #
        if str(type(txt)) == "<type 'file'>":
            txt.seek(0)
            txt = txt.read()
        #
        if encrypt: # If text MUST be encrypted first.
            val = self.encrypt(txt, pre, enc, post, pwd)
            if not val:
                return
        else: # Else, the text is already encrypted.
            val = txt
        #
        # Calculate the edge of the square.
        edge = int(math.ceil(math.sqrt(len(val)/4)))
        # Calculate blank pixels.
        blank = (edge * edge - len(val)/4) / 2
        # Explode the encrypted string.
        list_val = list(val)[::-1]
        # New square image.
        print('Creating new image, %ix%i, blank=%i, string to encode is %i characters.' % (edge, edge, blank, len(val)))
        im = Image.new('RGBA', (edge, edge))
        # Load pixels...
        pix = im.load()
        #
        for i in range(edge):
            for j in range(edge):
                #
                if blank:
                    blank -= 1
                    pix[j, i] = (255, 255, 255, 255)
                    continue
                #
                _r = _g = _b = _a = 255
                #
                if len(list_val) >= 1:
                    _r = ord(list_val.pop())
                if len(list_val) >= 1:
                    _g = ord(list_val.pop())
                if len(list_val) >= 1:
                    _b = ord(list_val.pop())
                if len(list_val) >= 1:
                    _a = ord(list_val.pop())
                #
                pix[j, i] = (_r, _g, _b, _a)
                #
        #
        try:
            im.save(path, format='PNG', optimize=True)
        except:
            print('Cannot save PNG file "%s" !' % path)
        #

    def fromImage(self, pre, enc, post, pwd, path, decrypt=True):
        #
        if not os.path.exists(path):
            print('Cannot find path "%s" !' % path)
            return
        #
        try:
            im = Image.open(path, 'r')
        except:
            print('Image "%s" is not a valid RGBA PNG !' % path)
            return
        #
        # Load pixels...
        pix = im.load()
        list_val = []
        #
        for i in range(im.size[1]):
            for j in range(im.size[0]):
                rgba = pix[j, i]
                for v in rgba:
                    if v and v != 255:
                        list_val.append(unichr(v))
        #
        if decrypt: # If the text MUST be decrypted.
            final = re.sub('[<[{(]?#[)}\]>]?[0-9a-zA-Z ]*:[0-9a-zA-Z ]*:[0-9a-zA-Z ]*[<[{(]?#[)}\]>]?', '', ''.join(list_val))
            val = self.decrypt(final, pre, enc, post, pwd)
            #
            if not val:
                print(self.error)
            else:
                return val
        else: # Else, don't decrypt.
            val = ''.join(list_val)
            return val
        #

class Window(QtGui.QMainWindow):

    def __init__(self):
        '''
        Init function.
        '''
        super(Window, self).__init__()
        self.resize(800, 600)
        self.setWindowTitle('Live Crypt')
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
        self.saveImage = QtGui.QPushButton('Export PNG', self.centralWidget) # Left side.
        self.setFormatting = QtGui.QCheckBox('Formatted text', self.centralWidget) # Left side.
        self.nrLettersL = QtGui.QLabel('', self.centralWidget) # Left side.

        self.preDecrypt = QtGui.QComboBox(self.centralWidget)    # Right side.
        self.comboDecrypt = QtGui.QComboBox(self.centralWidget)  # Right side.
        self.postDecrypt = QtGui.QComboBox(self.centralWidget)   # Right side.
        self.linePasswordR = QtGui.QLineEdit(self.centralWidget) # Right side.
        self.checkPwdR = QtGui.QCheckBox('<- Pwd', self.centralWidget) # Right side.
        self.loadImage = QtGui.QPushButton('Import PNG', self.centralWidget) # Right side.
        self.nrLettersR = QtGui.QLabel('', self.centralWidget) # Right side.

        self.layout.addWidget(self.buttonCryptMode, 1, 1, 1, 5)
        self.layout.addWidget(self.buttonDecryptMode, 1, 6, 1, 5)

        self.layout.addWidget(self.preProcess, 2, 1, 1, 1)
        self.layout.addWidget(self.comboCrypt, 2, 2, 1, 1)
        self.layout.addWidget(self.postProcess, 2, 3, 1, 1)
        self.layout.addWidget(self.preDecrypt, 2, 6, 1, 1)
        self.layout.addWidget(self.comboDecrypt, 2, 7, 1, 1)
        self.layout.addWidget(self.postDecrypt, 2, 8, 1, 1)
        self.layout.addWidget(self.setFormatting, 21, 3, 1, 1)

        self.layout.addWidget(self.saveImage, 21, 1, 1, 1)
        self.layout.addWidget(self.nrLettersL, 21, 5, 1, 1)
        self.layout.addWidget(self.loadImage, 21, 6, 1, 1)
        self.layout.addWidget(self.nrLettersR, 21, 10, 1, 1)

        self.layout.addWidget(self.linePasswordL, 3, 1, 1, 4)
        self.layout.addWidget(self.checkPwdL, 3, 5, 1, 1)
        self.layout.addWidget(self.linePasswordR, 3, 6, 1, 4)
        self.layout.addWidget(self.checkPwdR, 3, 10, 1, 1)

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
        #
        MIN = 110
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
        for scramble in sorted(SCRAMBLE.keys()):
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
        for encode in sorted(ENCODE.keys()):
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
        self.saveImage.clicked.connect(self.onSave)
        self.loadImage.clicked.connect(self.onLoad)
        self.setFormatting.toggled.connect(self.onLeftTextChanged)
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
        final = self.SE.encrypt(txt, pre, enc, post, pwd)
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
        pwd = self.linePasswordR.text()
        L = len(pwd)
        pwd += 'X' * ( (((L/16)+1)*16) - L )
        txt = self.rightText.toPlainText()
        #
        try:
            info = re.search('[<[{(]?#[)}\]>]?([0-9a-zA-Z ]*:[0-9a-zA-Z ]*:[0-9a-zA-Z ]*)[<[{(]?#[)}\]>]?', txt).group(1)
            self.postDecrypt.setCurrentIndex( self.postDecrypt.findText(info.split(':')[0], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.comboDecrypt.setCurrentIndex( self.comboDecrypt.findText(info.split(':')[1], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.preDecrypt.setCurrentIndex( self.preDecrypt.findText(info.split(':')[2], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            txt = re.sub('[<[{(]?#[)}\]>]?[0-9a-zA-Z ]*:[0-9a-zA-Z ]*:[0-9a-zA-Z ]*[<[{(]?#[)}\]>]?', '', txt)
        except:
            pass
        #
        # This must be right here.
        pre = self.preDecrypt.currentText()
        enc = self.comboDecrypt.currentText()
        post = self.postDecrypt.currentText()
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
        f = QtGui.QFileDialog()
        path = f.getSaveFileName(self, 'Save crypted text', os.getcwd(), 'PNG Images (*.png)')
        if not path:
            return
        #
        # Save all pre/enc/post operations.
        pre = self.preProcess.currentText()
        enc = self.comboCrypt.currentText()
        post = self.postProcess.currentText()
        pwd = self.linePasswordL.text()
        # Text from rigth side.
        txt = self.rightText.toPlainText()
        #
        self.SE.toImage(txt, pre, enc, post, pwd, path, encrypt=False)
        #

    def onLoad(self):
        #
        f = QtGui.QFileDialog()
        path = f.getOpenFileName(self, 'Load crypted text', os.getcwd(), 'PNG Images (*.png)')
        if not path:
            return
        #
        val = self.SE.fromImage(pre=None, enc=None, post=None, pwd=None, path=path, decrypt=False)
        if val:
            self.rightText.setPlainText(val)
        #
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



