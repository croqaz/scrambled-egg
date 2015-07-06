THIS SOFTWARE IS NO LONGER MAINTAINED AND MIGHT HAVE BUGS.

PLEASE USE AT YOUR OWN RISK.

Easily encrypt your messages using  **AES, ARC2, Blowfish, CAST, DES3 or RSA**, then encode the result in a printable form, using  **Base64, Base32, HEX, Quopri, string escape, UU, XML or Json**.<br>
The resulted string can be copied and sent on e-mail as <b>text</b>, or can be saved as <b>XML, Json</b> or <b>UU</b>, or can be transformed into a little <b>PNG image</b>.<br>
<br>
For example, the message  "<i>look behind the old desk</i>", crypted with AES, with password "<i>acorn1955</i>" would become:<br>
<ul><li>GAYic8DgN23tf/fN6UXUlETNNJENbNyi8tRjpsyVkJs= (in <b>Base64</b>)<br>
</li><li>18062273c0e0376ded7ff7cde945d49444cd34910d6cdca2f2d463a6cc95909b (in <b>HEX</b>)<br>
</li><li>=18=06"s=C0=E07m=ED=7F=F7=CD=E9E=D4=94D=CD4=91\nl=DC=A2=F2=D4c=A6=CC=95=90=\n=9B (<b>Quopri</b>)<br>
</li><li>\x18\x06"s\xc0\xe07m\xed\x7f\xf7\xcd\xe9E\xd4\x94D\xcd4\x91\rl\xdc\xa2\xf2\xd4c\xa6\xcc\x95\x90\x9b (with <b>string escape</b>)<br>
<i><b>The password is not stored inside the message</b></i>. It's impossible for someone to decrypt the message, unless it knows, or guesses your password.<br>
<br>
This software was tested with hundreds of different files: images, music, office documents, executable files, using random passwords from <i>1 to 196</i> characters. The application is stable (the files are intact with all encryption + decryption methods).<br>
Written in Python, it works on <b>Windows</b>, <b>Ubuntu</b>, <b>Fedora</b> and <b>OpenSUSE</b>. It should also work on <b>Mac OS</b>, if you execute the source "scrambled_egg.py".<br>
<br>
Useful articles:<br>
<a href='http://en.wikipedia.org/wiki/Cipher_security_summary'>http://en.wikipedia.org/wiki/Cipher_security_summary</a><br>
<a href='http://en.wikipedia.org/wiki/Password_strength'>http://en.wikipedia.org/wiki/Password_strength</a><br>
<a href='http://en.wikipedia.org/wiki/Password_cracking'>http://en.wikipedia.org/wiki/Password_cracking</a><br>
<a href='https://www.microsoft.com/security/pc-security/password-checker.aspx'>https://www.microsoft.com/security/pc-security/password-checker.aspx</a><br>
<br><br>
<b>Example print screen on Windows (Encryption with ZLIB + AES + Base64)</b><br><br>
<a href='http://scrambled-egg.googlecode.com/svn/wiki/segg1_0.4.PNG'>http://scrambled-egg.googlecode.com/svn/wiki/segg1_0.4.PNG</a><br>
<br><br>
<b>Another example print screen on Windows (Decryption with BZ2 + RSA + Base64)</b><br><br>
<a href='http://scrambled-egg.googlecode.com/svn/wiki/segg2_0.4.PNG'>http://scrambled-egg.googlecode.com/svn/wiki/segg2_0.4.PNG</a><br>
<br><br>
<b>Print screen in Gnome3 on Fedora</b><br><br>
<a href='http://scrambled-egg.googlecode.com/svn/wiki/segg3_0.4.PNG'>http://scrambled-egg.googlecode.com/svn/wiki/segg3_0.4.PNG</a><br>
<br><br>
<b>Le Petit Prince by Antoine de Saint Exupery</b> (compressed BZ2 + AES + HEX) (password is <i><b>Le Petit Prince</b></i>) (original 206,867 characters)<br><br>
<img src='http://scrambled-egg.googlecode.com/svn/wiki/lpp_0.3.png' /><br>
<br><br>
<b>The Prophet by Khalil Gibran</b> (compressed BZ2 + Blowfish + HEX) (password is <i><b>The Prophet</b></i>) (original  155,264 characters)<br><br>
<img src='http://scrambled-egg.googlecode.com/svn/wiki/tp_0.3.png' /><br>
<br><br>
<a href='http://www.softpedia.com/get/Security/Encrypting/Scrambled-Egg.shtml'>
<img src='http://www.softpedia.com/base_img/softpedia_free_award_f.gif' /></a>
<br>