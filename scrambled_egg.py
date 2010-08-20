#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.blogspot.com.
# ---

import os, sys
import re

from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import CAST
from Crypto.Cipher import DES3

import sip
sip.setapi('QString', 2)
sip.setapi('QVariant', 2)

from PyQt4 import QtCore
from PyQt4 import QtGui

#
SCRAMBLE = ['None', 'ZLIB', 'BZ2', 'ROT13']
ENC = ['AES', 'Blowfish', 'CAST', 'DES3', 'None']
ENCODE = ['Base64 Codec', 'HEX Codec', 'Quopri Codec', 'String Escape', 'UU Codec']
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

        self.centralWidget = QtGui.QWidget(self) # Central Widget.
        self.setCentralWidget(self.centralWidget)
        self.statusBar = QtGui.QStatusBar(self)  # Status Bar.
        self.setStatusBar(self.statusBar)
        self.layout = QtGui.QGridLayout(self.centralWidget) # Main Layout.
        self.centralWidget.setLayout(self.layout)

        self.leftText = QtGui.QPlainTextEdit(self.centralWidget)  # To write clean text.
        self.rightText = QtGui.QPlainTextEdit(self.centralWidget) # To view encrypted text.

        self.buttonCryptMode = QtGui.QPushButton('Encrypt Mode', self.centralWidget)
        self.buttonDecryptMode = QtGui.QPushButton('Decrypt Mode', self.centralWidget)

        self.preProcess = QtGui.QComboBox(self.centralWidget)  # Left side.
        self.comboCrypt = QtGui.QComboBox(self.centralWidget)  # Left side.
        self.postProcess = QtGui.QComboBox(self.centralWidget) # Left side.
        self.linePasswordL = QtGui.QLineEdit(self.centralWidget) # Left side.
        self.buttonLGo = QtGui.QPushButton('Encrypt!', self.centralWidget)

        self.preDecrypt = QtGui.QComboBox(self.centralWidget)    # Right side.
        self.comboDecrypt = QtGui.QComboBox(self.centralWidget)  # Right side.
        self.postDecrypt = QtGui.QComboBox(self.centralWidget)   # Right side.
        self.linePasswordR = QtGui.QLineEdit(self.centralWidget) # Right side.
        self.buttonRGo = QtGui.QPushButton('Decrypt!', self.centralWidget)

        self.layout.addWidget(self.buttonCryptMode, 1, 1, 1, 5)
        self.layout.addWidget(self.buttonDecryptMode, 1, 6, 1, 5)

        self.layout.addWidget(self.linePasswordL, 2, 1, 1, 4)
        self.layout.addWidget(self.buttonLGo, 2, 5, 1, 1)
        self.layout.addWidget(self.linePasswordR, 2, 6, 1, 4)
        self.layout.addWidget(self.buttonRGo, 2, 10, 1, 1)

        self.layout.addWidget(self.preProcess, 3, 1, 1, 1)
        self.layout.addWidget(self.comboCrypt, 3, 2, 1, 1)
        self.layout.addWidget(self.postProcess, 3, 3, 1, 1)

        self.layout.addWidget(self.preDecrypt, 3, 6, 1, 1)
        self.layout.addWidget(self.comboDecrypt, 3, 7, 1, 1)
        self.layout.addWidget(self.postDecrypt, 3, 8, 1, 1)

        self.layout.addWidget(self.leftText, 5, 1, 10, 5)
        self.layout.addWidget(self.rightText, 5, 6, 10, 5)

        self.__setup() # Prepair all components!
        self.__connect() # Connect all components!

    def __setup(self):
        '''
        Setup all components.
        '''
        #
        self.buttonRGo.setDisabled(True)
        self.rightText.setReadOnly(True)
        #
        # Toogle buttons.
        self.buttonCryptMode.setCheckable(True)
        self.buttonCryptMode.setChecked(True)
        self.buttonCryptMode.setToolTip('Switch to Encryption mode')
        self.buttonDecryptMode.setCheckable(True)
        self.buttonDecryptMode.setToolTip('Switch to Decryption mode')
        #
        # Password fields.
        #self.linePasswordL.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordL.setToolTip('Type password here; it will be used for encrypting the text')
        self.linePasswordL.setMaxLength(99)
        #self.linePasswordR.setEchoMode(QtGui.QLineEdit.Password)
        self.linePasswordR.setToolTip('Password for decrypting the text')
        self.linePasswordR.setMaxLength(99)
        self.linePasswordR.setDisabled(True)
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
        for enc in ENC:
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
        self.buttonCryptMode.clicked.connect(self.onCryptMode)
        #
        self.linePasswordR.textChanged.connect(self.onRightTextChanged)
        self.rightText.textChanged.connect(self.onRightTextChanged)
        self.buttonDecryptMode.clicked.connect(self.onDecryptMode)
        #
        self.buttonLGo.clicked.connect(self.onLeftTextChanged)
        self.preProcess.currentIndexChanged.connect(self.onLeftTextChanged)
        self.comboCrypt.currentIndexChanged.connect(self.onLeftTextChanged)
        self.postProcess.currentIndexChanged.connect(self.onLeftTextChanged)
        #
        self.buttonRGo.clicked.connect(self.onRightTextChanged)
        self.preDecrypt.currentIndexChanged.connect(self.onRightTextChanged)
        self.comboDecrypt.currentIndexChanged.connect(self.onRightTextChanged)
        self.postDecrypt.currentIndexChanged.connect(self.onRightTextChanged)
        #

    def onCryptMode(self):
        #
        self.buttonCryptMode.setChecked(True)
        self.buttonDecryptMode.setChecked(False)
        #
        self.buttonLGo.setDisabled(False)
        self.buttonRGo.setDisabled(True)
        #
        self.linePasswordL.setDisabled(False)
        self.leftText.setReadOnly(False)
        self.linePasswordR.setDisabled(True)
        self.rightText.setReadOnly(True)
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
        self.buttonLGo.setDisabled(True)
        self.buttonRGo.setDisabled(False)
        #
        self.linePasswordL.setDisabled(True)
        self.leftText.setReadOnly(True)
        self.linePasswordR.setDisabled(False)
        self.rightText.setReadOnly(False)
        #
        self.postDecrypt.setCurrentIndex(self.preProcess.currentIndex())
        self.comboDecrypt.setCurrentIndex(self.comboCrypt.currentIndex())
        self.preDecrypt.setCurrentIndex(self.postProcess.currentIndex())
        #

    def __error(self, step, pre, enc, post):
        #
        if step==1:
            pre += ' (ERROR!)'
        elif step==2:
            enc += ' (ERROR!)'
        elif step==3:
            post += ' (ERROR!)'
        #
        self.leftText.clear()
        self.statusBar.setStyleSheet('color: red;')
        self.statusBar.showMessage('  Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
        #

    def onLeftTextChanged(self):
        #
        if not self.buttonCryptMode.isChecked() or not self.leftText.toPlainText():
            return
        #
        pre = self.preProcess.currentText()
        enc = self.comboCrypt.currentText()
        post = self.postProcess.currentText()
        #
        if self.buttonCryptMode.isChecked():
            self.statusBar.setStyleSheet('color: blue;')
            self.statusBar.showMessage('  Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
        #
        self.postDecrypt.setCurrentIndex(self.preProcess.currentIndex())
        self.comboDecrypt.setCurrentIndex(self.comboCrypt.currentIndex())
        self.preDecrypt.setCurrentIndex(self.postProcess.currentIndex())
        #
        pwd = self.linePasswordL.text().strip('X')
        L = len(pwd)
        pwd += 'X' * ( (((L/16)+1)*16) - L )
        #
        txt = self.leftText.toPlainText()
        #
        if pre == 'None':
            pass
        if pre == 'ZLIB':
            txt = txt.encode('zlib')
        if pre == 'BZ2':
            txt = txt.encode('bz2')
        if pre == 'ROT13':
            txt = txt.encode('rot13')
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
        #
        if post == 'Base64 Codec':
            self.rightText.setPlainText('<#>%s:%s:%s<#>' % (pre, enc, post.replace(' Codec','')) + encrypted.encode('base64'))
        elif post == 'HEX Codec':
            self.rightText.setPlainText('<#>%s:%s:%s<#>' % (pre, enc, post.replace(' Codec','')) + encrypted.encode('hex'))
        elif post == 'Quopri Codec':
            self.rightText.setPlainText('<#>%s:%s:%s<#>' % (pre, enc, post.replace(' Codec','')) + encrypted.encode('quopri_codec'))
        elif post == 'String Escape':
            self.rightText.setPlainText('<#>%s:%s:%s<#>' % (pre, enc, post) + encrypted.encode('string_escape'))
        elif post == 'UU Codec':
            self.rightText.setPlainText('<#>%s:%s:%s<#>' % (pre, enc, post.replace(' Codec','')) + encrypted.encode('uu'))
        #

    def onRightTextChanged(self):
        #
        if not self.buttonDecryptMode.isChecked() or not self.rightText.toPlainText():
            return
        #
        pwd = self.linePasswordR.text().strip('X')
        L = len(pwd)
        pwd += 'X' * ( (((L/16)+1)*16) - L )
        txt = self.rightText.toPlainText()
        #
        try:
            info = re.search('<#>([0-9a-zA-Z ]*:[0-9a-zA-Z ]*:[0-9a-zA-Z ]*)<#>', txt).group(1)
            self.postDecrypt.setCurrentIndex( self.postDecrypt.findText(info.split(':')[0], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.comboDecrypt.setCurrentIndex( self.comboDecrypt.findText(info.split(':')[1], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            self.preDecrypt.setCurrentIndex( self.preDecrypt.findText(info.split(':')[2], QtCore.Qt.MatchFlag(QtCore.Qt.MatchContains)) )
            txt = re.sub('<#>[0-9a-zA-Z ]*:[0-9a-zA-Z ]*:[0-9a-zA-Z ]*<#>', '', txt)
        except:
            info = ''
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
        #
        if enc != 'None':
            try: txt = o.decrypt(txt).rstrip('X')
            except: self.__error(2, pre, enc, post) ; return
        #
        if post == 'None':
            pass
        if post == 'ZLIB':
            try: txt = txt.decode('zlib')
            except: self.__error(3, pre, enc, post) ; return
        if post == 'BZ2':
            try: txt = txt.decode('bz2')
            except: self.__error(3, pre, enc, post) ; return
        if post == 'ROT13':
            try: txt = txt.decode('rot13')
            except: self.__error(3, pre, enc, post) ; return
        #
        self.leftText.setPlainText(txt)
        #

#

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())

# Eof()

