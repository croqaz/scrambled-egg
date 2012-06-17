
# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import re
import wx

from scrambled_egg import ScrambledEgg, NO_TAGS, __version__
from scrambled_egg import SCRAMBLE, SCRAMBLE_D, ENC, ENCODE, ENCODE_D


# # #

def findg(g):
    for i in g:
        if i: return ''.join(i.split())

# # #


class Window(wx.Frame):

    def __init__(self):

        wx.Frame.__init__(self, parent=None, title='Scrambled Egg GUI', size=(800, 600))

        self.SetMinSize((800, 300))
        panel = wx.Panel(self)
        hbox = wx.BoxSizer(wx.HORIZONTAL)

        self.statusBar = self.CreateStatusBar()
        self.statusBar.SetStatusText('Ready')

        self.SE = ScrambledEgg()


        # Left vertical layout
        leftbag = wx.BoxSizer(wx.VERTICAL)

        # Combo bag left
        cbagl = wx.BoxSizer(wx.HORIZONTAL)
        self.preProcess  = wx.ComboBox(panel, -1, SCRAMBLE[0],
                size=(130, -1), choices=SCRAMBLE, style=wx.CB_READONLY) # Left side
        self.comboCrypt  = wx.ComboBox(panel, -1, ENC.keys()[0],
                size=(130, -1), choices=ENC.keys(), style=wx.CB_READONLY) # Left side
        self.postProcess = wx.ComboBox(panel, -1, ENCODE[0],
                size=(130, -1), choices=ENCODE, style=wx.CB_READONLY)   # Left side
        #
        cbagl.Add(self.preProcess)
        cbagl.Add(self.comboCrypt)
        cbagl.Add(self.postProcess)

        self.buttonCryptMode = wx.ToggleButton(panel, label='Encryption Mode is Enabled')
        self.buttonCryptMode.SetValue(True)

        # Password bag left
        pbagl = wx.BoxSizer(wx.HORIZONTAL)
        self.linePasswordL = wx.TextCtrl(panel, -1)  # Left password line
        self.checkPwdL   = wx.CheckBox(panel, -1, size=(85, -1), label='<- Pwd') # Left side
        #
        pbagl.Add(self.linePasswordL, proportion=5, flag=wx.EXPAND)
        pbagl.Add(self.checkPwdL,     proportion=1, flag=wx.ALIGN_CENTER_VERTICAL)

        # Left check boxes
        bbagl = wx.BoxSizer(wx.HORIZONTAL)
        self.setTags    = wx.CheckBox(panel, -1, size=(105, 25), label='Tags')   # Left side
        self.setTags.SetValue(True)
        self.nrLettersL = wx.StaticText(panel, -1, '')
        #
        bbagl.Add(self.setTags,    proportion=5, flag=wx.EXPAND)
        bbagl.Add(self.nrLettersL, proportion=1, flag=wx.ALIGN_CENTER_VERTICAL|wx.ALIGN_CENTER_HORIZONTAL)

        self.leftText  = wx.TextCtrl(panel, style=wx.TE_MULTILINE) # Plain text

        # Append in left vertical layout
        leftbag.Add(self.buttonCryptMode, border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        leftbag.Add(cbagl,                border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        leftbag.Add(pbagl,                border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        leftbag.Add(self.leftText,        border=3, proportion=10, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        leftbag.Add(bbagl,                border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)


        # Right vertical layout
        rightbag = wx.BoxSizer(wx.VERTICAL)

        # Combo bag right
        cbagr = wx.BoxSizer(wx.HORIZONTAL)
        self.preDecrypt   = wx.ComboBox(panel, -1, SCRAMBLE[0],
                size=(130, -1), choices=SCRAMBLE, style=wx.CB_READONLY) # Right side
        self.comboDecrypt = wx.ComboBox(panel, -1, ENC.keys()[0],
                size=(130, -1), choices=ENC.keys(), style=wx.CB_READONLY) # Right side
        self.postDecrypt  = wx.ComboBox(panel, -1, ENCODE[0],
                size=(130, -1), choices=ENCODE, style=wx.CB_READONLY)    # Right side

        cbagr.Add(self.preDecrypt)
        cbagr.Add(self.comboDecrypt)
        cbagr.Add(self.postDecrypt)

        self.buttonDecryptMode = wx.ToggleButton(panel, label='Decryption Mode')
        self.buttonDecryptMode.SetValue(False)

        # Password bag right
        pbagr = wx.BoxSizer(wx.HORIZONTAL)
        self.linePasswordR =  wx.TextCtrl(panel, -1)  # Right password line
        self.checkPwdR    = wx.CheckBox(panel, -1, size=(85, -1), label='<- Pwd') # Right side
        #
        pbagr.Add(self.linePasswordR, proportion=5, flag=wx.EXPAND)
        pbagr.Add(self.checkPwdR,     proportion=1, flag=wx.ALIGN_CENTER_VERTICAL)

        # Right buttons
        bbagr = wx.BoxSizer(wx.HORIZONTAL)
        self.loadFile = wx.Button(panel,  size=(105, 25), label='Import')  # Right side
        self.saveFile = wx.Button(panel,  size=(105, 25), label='Export')  # Right side
        self.helpButton = wx.Button(panel, size=(105, 25), label='Help !') # Right side
        self.nrLettersR = wx.StaticText(panel, -1, '')
        #
        bbagr.Add(self.loadFile)
        bbagr.Add(self.saveFile)
        bbagr.Add(self.helpButton)
        bbagr.Add(self.nrLettersR, flag=wx.ALIGN_CENTER_VERTICAL|wx.ALIGN_CENTER_HORIZONTAL)

        self.rightText = wx.TextCtrl(panel, style=wx.TE_MULTILINE) # Encrypted text

        # Append in right vertical layout
        rightbag.Add(self.buttonDecryptMode, border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        rightbag.Add(cbagr,                  border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        rightbag.Add(pbagr,                  border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        rightbag.Add(self.rightText,         border=3, proportion=10, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)
        rightbag.Add(bbagr,                  border=3, flag=wx.EXPAND|wx.RIGHT|wx.BOTTOM)


        hbox.Add(leftbag,  proportion=1, flag=wx.EXPAND|wx.ALL, border=5)
        hbox.Add(rightbag, proportion=1, flag=wx.EXPAND|wx.ALL, border=5)
        panel.SetSizer(hbox)

        self._bind_events()

        self.Center()
        self.Show(True)


    def _bind_events(self):

        self.buttonCryptMode.Bind( wx.EVT_TOGGLEBUTTON, self.onCryptMode)
        self.buttonDecryptMode.Bind(wx.EVT_TOGGLEBUTTON, self.onDecryptMode)

        self.linePasswordL.Bind(wx.EVT_TEXT, self.onLeftTextChanged)
        self.leftText.Bind(wx.EVT_TEXT, self.onLeftTextChanged)

        self.linePasswordR.Bind(wx.EVT_TEXT, self.onRightTextChanged)
        self.rightText.Bind(wx.EVT_TEXT, self.onRightTextChanged)

        self.preProcess.Bind(wx.EVT_COMBOBOX, self.onLeftTextChanged)
        self.comboCrypt.Bind(wx.EVT_COMBOBOX, self.onLeftTextChanged)
        self.postProcess.Bind(wx.EVT_COMBOBOX, self.onLeftTextChanged)

        self.preDecrypt.Bind(wx.EVT_COMBOBOX, self.onRightTextChanged)
        self.comboDecrypt.Bind(wx.EVT_COMBOBOX, self.onRightTextChanged)
        self.postDecrypt.Bind(wx.EVT_COMBOBOX, self.onRightTextChanged)

        self.helpButton.Bind(wx.EVT_BUTTON, self.onHelp)

        # ACTION !
        self.onCryptMode(None)


    def onCryptMode(self, e):

        self.buttonCryptMode.SetValue(True)
        self.buttonCryptMode.SetLabel('Encrypt Mode is Enabled')
        self.buttonDecryptMode.SetValue(False)
        self.buttonDecryptMode.SetLabel('Decrypt Mode')
        #
        self.linePasswordL.Enable(True)
        #self.lineRSAPathL.Enable(True)
        #self.buttonBrowseRSAL.Enable(True)
        self.leftText.Enable(True)
        #
        self.linePasswordR.Enable(False)
        #self.lineRSAPathR.Enable(False)
        #self.buttonBrowseRSAR.Enable(False)
        self.rightText.Enable(False)
        #
        self.checkPwdL.Enable(True)
        self.checkPwdR.Enable(False)
        #
        self.preProcess.SetSelection(self.preDecrypt.GetCurrentSelection())
        self.comboCrypt.SetSelection(self.comboDecrypt.GetCurrentSelection())
        self.postProcess.SetSelection(self.postDecrypt.GetCurrentSelection())
        #


    def onDecryptMode(self, e):

        self.buttonCryptMode.SetValue(False)
        self.buttonCryptMode.SetLabel('Encrypt Mode')
        self.buttonDecryptMode.SetValue(True)
        self.buttonDecryptMode.SetLabel('Decrypt Mode is Enabled')
        #
        self.linePasswordL.Enable(False)
        #self.lineRSAPathL.Enable(False)
        #self.buttonBrowseRSAL.Enable(False)
        self.leftText.Enable(False)
        #
        self.linePasswordR.Enable(True)
        #self.lineRSAPathR.Enable(True)
        #self.buttonBrowseRSAR.Enable(True)
        self.rightText.Enable(True)
        #
        self.checkPwdL.Enable(False)
        self.checkPwdR.Enable(True)
        #
        self.postDecrypt.SetSelection(self.postProcess.GetCurrentSelection())
        self.comboDecrypt.SetSelection(self.comboCrypt.GetCurrentSelection())
        self.preDecrypt.SetSelection(self.preProcess.GetCurrentSelection())
        #


    def onLeftTextChanged(self, e):

        if not self.buttonCryptMode.GetValue():
            return

        # Save all pre/enc/post operations.
        pre = self.preProcess.GetValue()
        enc = self.comboCrypt.GetValue()
        post = self.postProcess.GetValue()

        if not self.leftText.GetValue():
            self.rightText.Clear()
            return

        pwd = self.linePasswordL.GetValue().encode()
        tags = self.setTags.GetValue()
        txt = self.leftText.GetValue().encode()

        self.postDecrypt.SetSelection(self.postProcess.GetCurrentSelection())
        self.comboDecrypt.SetSelection(self.comboCrypt.GetCurrentSelection())
        self.preDecrypt.SetSelection(self.preProcess.GetCurrentSelection())

        # Encrypt the text...
        final = self.SE.encrypt(txt, pre, enc, post, pwd, tags)

        if final:
            self.statusBar.SetForegroundColour(wx.BLUE)
            self.statusBar.SetStatusText(' Encryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
            self.rightText.SetValue(final)
            self.nrLettersL.SetLabel('Plain: %i' % len(txt))
            self.nrLettersR.SetLabel('  Enc: %i' % len(final))
        else:
            self.rightText.Clear()
            self.statusBar.SetForegroundColour(wx.RED)
            self.statusBar.SetStatusText(self.SE.error)


    def onRightTextChanged(self, e):

        if not self.buttonDecryptMode.GetValue():
            return

        txt = self.rightText.GetValue().encode()

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

            # <#>ZL:B:H<#>fcef508d0b565c9936fa500ef517ed4b

            pre = {ENCODE_D[k]:k for k in ENCODE_D}[pre]
            enc = {ENC[k]:k for k in ENC}[enc]
            post = {SCRAMBLE_D[k]:k for k in SCRAMBLE_D}[post]

            self.postDecrypt.SetStringSelection(pre)
            self.comboDecrypt.SetStringSelection(enc)
            self.preDecrypt.SetStringSelection(post)
        except:
            pass

        # This must be right here.
        pre = self.postDecrypt.GetValue()
        enc = self.comboDecrypt.GetValue()
        post = self.preDecrypt.GetValue()
        pwd = self.linePasswordR.GetValue().encode()

        if not txt:
            self.leftText.Clear()
            return

        self.preProcess.SetSelection(self.preDecrypt.GetCurrentSelection())
        self.comboCrypt.SetSelection(self.comboDecrypt.GetCurrentSelection())
        self.postProcess.SetSelection(self.postDecrypt.GetCurrentSelection())

        # Decrypt the text...
        final = self.SE.decrypt(txt, pre, enc, post, pwd)

        if final:
            self.statusBar.SetForegroundColour(wx.BLUE)
            self.statusBar.SetStatusText(' Decryption mode   step 1: %s ,   step 2: %s ,   step 3: %s' % (pre, enc, post))
            self.leftText.SetValue(final)
            self.nrLettersL.SetLabel('Plain: %i' % len(final))
            self.nrLettersR.SetLabel('  Enc: %i' % len(txt))
        else:
            self.leftText.Clear()
            self.statusBar.SetForegroundColour(wx.RED)
            self.statusBar.SetStatusText(self.SE.error)


    def onHelp(self, e):
        #
        dia = wx.MessageDialog(None,
            'Copyright (C) 2010-2012: Cristi Constantin, all rights reserved.\n'
            'Website: http://scrambled-egg.googlecode.com/\n\n'
            'Scrambled-Egg is a software designed for encrypting your sensitive data.\n'
            'This is done in 3 steps: pre encryption, encryption, and post encryption.\n'
            'The input data can only be plain text.\n\n'
            'Step 1 can compress your data using ZLIB, or BZ2. This step is optional.\n'
            'Step 2 is the real encryption, for example with AES, or Blowfish.'
            'The password is used only in this step.\n'
            #'For <b>RSA</b> encryption, along with the password, you have to type the path to the public or private RSA key.<br>'
            'Step 3 will encode your data. This step is required, the rest are optional. '
            'There are a lot of encodings available, for example Base64, or HEX.\n\n'
            'This FREE program is distributed in the hope that it will be useful, but without any warranty.\n\n'
            'Enjoy!', 'Scrambled Egg %s Help' % __version__, wx.OK)
        dia.ShowModal()
        #


# # #

if __name__ == '__main__':

    app = wx.App(False)
    win = Window()
    app.MainLoop()

# # #
