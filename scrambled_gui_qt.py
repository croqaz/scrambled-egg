
# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os
import sys
import re
import json
import urllib
import platform
import subprocess

import sip
sip.setapi('QString', 2)
sip.setapi('QVariant', 2)

from PyQt4 import QtCore
from PyQt4 import QtGui

from scrambled_egg import ScrambledEgg, NO_TAGS, __version__
from scrambled_egg import SCRAMBLE, SCRAMBLE_D, ENC, ENCODE, ENCODE_D

C = {} # Config.
D = {} # Themes.

def findg(g):
    for i in g:
        if i: return ''.join(i.split())


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
        self.setWindowOpacity(0.9)
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
        self.setTags = QtGui.QCheckBox('No tags', self.centralWidget)    # Left side.
        self.showHTML = QtGui.QCheckBox('Show HTML', self.centralWidget) # Left side.

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
        self.layout.addWidget(self.container,           0, 1, 43, 12)
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

        self.layout.addWidget(self.leftText,            8, 2, 32, 5)
        self.layout.addWidget(self.rightText,           8, 7, 32, 5)

        self.layout.addWidget(self.setFormatting,       40, 2, 1, 1)
        self.layout.addWidget(self.setTags,             40, 3, 1, 1)
        self.layout.addWidget(self.showHTML,            40, 4, 1, 1)
        self.layout.addWidget(self.loadFile,            40, 7, 1, 1)
        self.layout.addWidget(self.saveFile,            40, 8, 1, 1)
        self.layout.addWidget(self.helpButton,          40, 9, 1, 1)

        self.layout.addWidget(self.nrLettersL,          40, 6, 1, 1)
        self.layout.addWidget(self.nrLettersR,          40, 11, 1, 1)

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
        self.setFormatting.setChecked(True)
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
            return matchobj.group(0).replace(b' ', b'&nbsp;')

        # Replacing all spaces with &nbsp;
        txt = re.sub(b'>([^<>]+)<(?!/style>)', spacerepl, txt)
        # Write the new file
        open('doc.htm', 'w').write(txt)

        # Process the file with Tidy
        if platform.uname()[0].lower() == 'windows':
            p = subprocess.Popen(['tidy.exe', '-config', 'tidy.txt', 'doc.htm']).wait()
        elif platform.uname()[0].lower() == 'linux':
            env = os.environ
            env.update({'LD_LIBRARY_PATH': os.getcwd()})
            p = subprocess.Popen(['./tidy', '-config', 'tidy.txt', 'doc.htm'], env=env).wait()
        else:
            print('Platform `%s` is not supported yet!\n' % platform.uname()[0])

        txt = open('doc.htm', 'r').read()
        # Delete the wrong/ obsolete tags
        txt = txt.replace(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"\n"http://www.w3.org/TR/html4/loose.dtd">\n', '')
        txt = txt.replace(b'<meta name="generator" content="HTML Tidy for Windows (vers 25 March 2009), see www.w3.org">\n', '')
        txt = txt.replace(b'<meta name="generator" content="HTML Tidy for Linux/x86 (vers 25 March 2009), see www.w3.org">\n', '')
        txt = txt.replace(b'<meta name="generator" content="HTML Tidy for Linux (vers 25 March 2009), see www.w3.org">\n', '')
        txt = txt.replace(b'<meta name="qrichtext" content="1">\n', '')
        txt = txt.replace(b'<title></title>\n', '')
        txt = txt.replace(b'</style>\n\n<style type="text/css">\n', '')
        txt = txt.replace(b'<br>\n', '\n')
        # The clean file, for debug...
        open('doc.htm', 'w').write(txt)

        return txt
        #

    def toggleHtml(self):
        #
        if self.showHTML.isChecked():
            vDlg = QtGui.QDialog(self.centralWidget)
            vDlg.setMinimumSize(C['W_WIDTH'], C['W_HEIGHT']-20)

            vDlg.text = QtGui.QPlainTextEdit(self.cleanupHtml( self.leftText.toHtml().encode('latin1') ), vDlg)

            vDlg.btnSave = QtGui.QPushButton('Save', vDlg)
            vDlg.btnSave.clicked.connect(
                lambda: vDlg.text.toPlainText().encode('latin1')
            )
            vDlg.btnCancel = QtGui.QPushButton('Cancel', vDlg)
            vDlg.btnCancel.clicked.connect(
                lambda: vDlg.reject()
            )

            layout = QtGui.QGridLayout(vDlg)
            layout.addWidget(vDlg.text, 1, 1, 2, 2)
            layout.addWidget(vDlg.btnSave, 3, 1)
            layout.addWidget(vDlg.btnCancel, 3, 2)
            vDlg.setLayout(layout)
            vRes = vDlg.exec_()

            print vRes

            self.showHTML.setChecked(False)
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
            txt = self.leftText.toHtml().encode('utf-8')
            # Cleanup HTML string.
            #txt = self.cleanupHtml(txt)
        else:
            txt = self.leftText.toPlainText().encode('utf-8')
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
            #final = self.cleanupHtml(final)
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
            '<br><b>Copyright (C) 2010-2012</b> : Cristi Constantin. All rights reserved.<br>'
            '<b>Website</b> : http://scrambled-egg.googlecode.com/<br><br>'
            'Scrambled-Egg is a software designed for encrypting your sensitive data.<br>'
            'This is done in <font color="blue"><b>3 steps</b></font> : <i>pre encryption</i>, <i>encryption</i>, and <i>post encryption</i>.<br>'
            'The input data can be : plain text, or formatted text (Microsoft Office or HTML).<br><br>'
            '<font color="blue"><b>Step 1</b></font> can compress your data using <b>ZLIB</b>, or <b>BZ2</b>. This step is optional.<br>'
            '<font color="blue"><b>Step 2</b></font> is the real encryption, for example with <b>AES</b>, or <b>Blowfish</b>. '
            'The password is used only in this step. '
            'For <b>RSA</b> encryption, along with the password, you have to type the path to the public or private RSA key.<br>'
            '<font color="blue"><b>Step 3</b></font> will encode your data. This step is required, the rest are optional. '
            'There are a lot of encodings available, for example <b>Base64</b>, or <b>HEX</b>.<br><br>'
            'This FREE program is distributed in the hope that it will be useful, but without any warranty.<br><br>'
            'Enjoy!')
        #

#

def loadConfig():

    script_path = os.path.abspath(__file__)
    base_path = os.path.split(script_path)[0] + '/config/'
    C = {}

    if os.path.exists(base_path):
        #try:
        c = open(base_path + 'config.json', 'r').read()
        C = json.loads(c)
        #except:
        #    print('Cannot load config: `{0}` ! Using builtin config !'.format(base_path + 'config.json'))

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

if __name__ == '__main__':

    if platform.uname()[0].lower() == 'linux':
        try: os.system('chmod +x tidy')
        except: pass

    C = loadConfig()
    D = loadThemes()
    app = QtGui.QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())

#
# Eof()
#
