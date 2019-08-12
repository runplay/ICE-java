# run ICE-java
![alt tag](http://www.runplay.com/rp/logo/logo-ice_196x196.png "run ICE Logo")
  
<b>Ice</b><br/>
Inclusive Compression Encryption<br/>
or<br/>
Ice Pack<br/>
or<br/>
Ice.with().chill().pack(); 
<br/><br/>
Ice is a small, single file, complete tool for Encrypting, Encoding and Compressing data; for storage or transport.<br/>
import the library, or drop the .java file into any project<br/>
Uses standard java only, so can be used anywhere, there should be no conflicts (does need javax.crypto.*)<br/>
Built to be fast to code and easy to debug, you can be done with one line of code.


<br/><br/>
<h2>Features</h2>

Full of features<br/>
✅ Encrypt, Compress, Encode easily with one line of code<br/>
✅ PGP inculded<br/>
✅ Includes a Base64 encoder (courtesy of Google) 🌿<br/>
✅ Includes on the fly Zip compression (no disk) 🌿<br/>
✅  Full access to tayloring the encryption methods. 🌿<br/>
✅  Async callback for deeper long encription routines<br/>
<br/><br/>

<h2>How to Use</h2>
<br/>Simplest use, to encrypt:<br/>
```bash
Pack encrypted = Ice
		.with(new Flavour())
		.chill("Text to encrypt","password")
		.pack();

```
<br/>and then to decrypt:<br/>
```bash
Pack decrypted = Ice
		.with(new Flavour())
		.chill("Text to encrypt","password")
		.unpack();

```
<br/>reading the Pack:<br/>
```bash
Pack pack = Ice.with.....

pack.toString(); // return a string version of the data
pack.toBytes(); // returns the bytes
pack.toStringUrlSafe() // return a string version of the data safe for http transport
pack.getTime() // time taken
pack.isSucess() // did the pack succeed
pack.getMessage() // if(!isSucess()) then a message will appear here, or null if success
pack.getException() // if an exception was thrown, can be null, also will be null if success
pack.writeFile(File file); // write the bytes to a file

```
<br/><br/><br/>
a more detailed version is in the Flavour (coming soon):<br/>
```bash

coming soon, see /test for now

```

<br/>
<br/>
<h2>Updates</h2>
v1.1.021 - First release<br/>
<br/><br/>












