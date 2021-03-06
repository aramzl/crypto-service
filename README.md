# Crypto Service

Combining [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) 
for a more secure AES encryption. (java implementation)

* Using Base64 from http://iharder.sourceforge.net/current/java/base64/ 
* Using Timebase algorithm from https://github.com/j256/two-factor-auth 
* Using java AES encryption

A new AES key is generated every 30 seconds with the TOTP algorithm.
The client needs the original AES key to decrypt the messages but the key-synchronization happens with the help of the TOTP.

### Usage

  ```
 CryptoService cs = new CryptoService(secret.getBytes(), ivParam.getBytes(), ivParamTimeBased.getBytes());
 ByteBuffer buffer = ByteBuffer.wrap("foobar".getBytes());
 ByteBuffer encryptedBuffer = cs.encryptTimeBased(buffer);
 ByteBuffer decryptedBuffer = cs.decryptTimeBased(encryptedBuffer);
 System.out.println(new String(decryptedBuffer.array())); 
 ```
