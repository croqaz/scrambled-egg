### Version 0.4 brings the following changes : ###
  * password enhancement. The key is derived from original password (using PBKDF2) making the encryption much stronger, even with short passwords;
  * added Json encoding and RSA encryption;
  * few bug fixes and a lot of GUI improvements, including drag & drop text in the left area, a HELP button, etc;
  * There are a lot of improvements, but backwards incompatible, that means you cannot decrypt text encrypted with Scrambled-Egg version 0.3.

### Version 0.3 brings the following changes : ###
  * better encryption. All modes use CBC;
  * images resulted from HEX codec are about 25-33% smaller than images resulted from Base64/32;
  * checkbox to show HTML;
  * better testing. The program is stable. Tested on hundreds of files (images, music, office documents, executables);
  * the GUI looks nicer.

### Version 0.2 brings quite some changes : ###
  * a lot of bug fixes;
  * stability obtained after MASSIVE testing;
  * all operations are faster;
  * added ARC2 encryption, Base32 and XML encodings;
  * import and export operations directly from GUI;
  * checkbox to show and hide pre/enc/post tags in resulted text.