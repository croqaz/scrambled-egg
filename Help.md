# Introduction #

Scrambled-Egg is made for compressing and encrypting your data.<br>
The input data can be : plain text, formatted text, or a binary file (currently not supported from GUI).<br>
The result can be kept/sent as printable plain text, or as a little square image.<br>
<br>
<h1>Details</h1>

First of all, Scrambled-Egg <b>is not</b> a text editor.<br>
If you want to use formatted text, write your text in a text processor (Microsoft Word, Open Office, etc), then paste, or drag and drop the formatted text in the <b>left text-box</b>.<br>
Scrambled-Egg supports HTML and the formatting will be remembered upon encryption/ decryption, if you check the "Formatted text" checkbox. If you don't, the text will be plain-text.<br>
<br>
The original data is scrambled in 3 steps :<br>
<ul><li>Step 1 (<b>pre processing</b>)  : No processing, ZLIB, BZ2, or ROT13<br>
</li><li>Step 2 (<b>real encryption</b>) : AES, ARC2, Blowfish, CAST, DES3, RSA, or No encryption<br>
</li><li>Step 3 (<b>post processing</b>) : Base64, Base32, HEX, Quopri, String escape, Json, XML, or UU Codec</li></ul>

All 3 steps are important, you <i>should</i> use them all.<br>
The password is optional, and it's only used in step 2 (encryption).<br>
Step 3 (post processing) is <b>required</b>, the rest are <b>optional</b>.<br>
<br>
The resulted string contains a <i>pre/enc/post tag</i> in this form:<br>
"<i><#>pre:encryption:post<#></i>", where :<br>
<ul><li>"<i>pre</i>" represents one of the values from Step 1,<br>
</li><li>"<i>encryption</i>" is one of the values from Step 2 and<br>
</li><li>"<i>post</i>" is a value from Step 3.</li></ul>

This <i>pre/enc/post tag</i> can be deleted when keeping/sending the scrambled data, but it's important if you don't remember, or don't know <i>how</i> to decrypt the data back !<br>
<br>
For example, if someone scrambles the data with BZ2 + DES3 + HEX, and you try to decrypt it with ZLIB + DES3 + HEX, it will fail. You will have to try all combinations of pre/enc/post operations, even if you already know the password !<br>
<br>
<h1>Tips</h1>

<ul><li><i>Never ever</i> use Quopri Codec with binary files (images, music, Doc/Xls files, executable files). The result after decoding might differ from the original file !<br>
</li><li>Base32 Codec is VERY slow, so never use it for large files (few MBs).<br>
</li><li>The GUI will freeze for a looong time if you try to encrypt/ decrypt more than 200.000-300.000 characters !<br>
</li><li>You must type a password in the Password Field, if you want to encrypt your files :) If you don't provide a password, the letter '<i>X</i>' is used.<br>
</li><li>The most common passwords are : 111111, 123456, 123456789, Password, iloveyou, princess, rockyou, abc123, Querty. Don't use common passwords for protecting your data.</li></ul>

<h1>A few examples</h1>

<ul><li>you <b>must</b> destroy the <i>evidence</i>! -(password 'dodo')-> <#>N:AES:64<#>SBGtCtZphIoz9CaUmMhVvCYDoXd7JfU6jzUCFEnNeTM=<br>
</li><li>no-one will know about your secret -(password 'ph0enix')-> <#>R:B:32<#>QJMR5WVZGBZJFGN4DVB5DOXDXOW5AXTQAKTDSPQ7RJNLPPJHKK3Q73AUBGMH4JJGOFVOFUJT65UU2===<br>
</li><li>Lorem ipsum dolor sit amet, ( ... ) Suspendisse potenti. (this text has 2000 characters) --> The resulted string has 1231 characters with BZ2/ AES/ Base64.