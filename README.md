# run ICE-java
![alt tag](http://www.runplay.com/rp/logo/logo-ice_196x196.png "run ICE Logo")
  
<b>Ice</b><br/>
Inclusive Compression Encryption<br/>
or<br/>
Ice Pack<br/>

<br/><br/>
Ice is a small, single file, complete tool for Encrypting, Encoding and Compressing data; for storage or transport.<br/>
import the library, or drop the .java file into any project<br/>
Uses standard java only, so can be used anywhere, there should be no conflicts (does need javax.crypto.*)<br/>
Built to be fast to code and easy to debug, you can be done with one line of code.


<br/><br/>
<h2>Features</h2>

Full of features<br/>
✅ Encrypt (AES), Compress (Zip & LZ77), Encode (B64) easily with one line of code<br/>
✅ PGP inculded<br/>
✅ Includes a Base64 encoder (courtesy of Google) 🌿<br/>
✅ Includes on the fly Zip compression (in memory) 🌿<br/>
✅  Full access to tayloring the encryption methods. 🌿<br/>
✅  Async callback for deeper long encription routines<br/>
<br/><br/>

<h2>How to Use</h2>
Appendix:<br/>
1 - Simple use<br/>
2 - Result methods<br/>
3 - Detailed use<br/>
4 - PGP use<br/>
5 - Async use<br/>
6 - Extra features<br/>
<br/>
Simplest method are not recommend as it uses defaults for Flavour, iv and salt, however depicts well the ease of use.
<br/>
<h3>1 - Simple use</h3>
<br/>to encrypt:<br/>

```bash
Pack encrypted = Ice
		.with(new Flavour())
		.freeze("Text or bytes[] to encrypt")
		.block("password")
		.pack();


```
<br/>and then to decrypt:<br/>

```bash
Pack decrypted = Ice
		.with(new Flavour())
		.freeze("Text or bytes[] to decrypt")
		.block("password")
		.unpack();

```
<br/>
<h3>2 - Result pack useful methods</h3>
<br/>reading the Pack:<br/>

```bash
Pack pack = Ice.with.....

pack.toString(); // return a string version of the data
pack.toBytes(); // returns the bytes
pack.toStringUrlSafe(); // return a string version of the data safe for http transport
pack.getTime(); // time taken
pack.isSucess(); // did the pack succeed
pack.getMessage(); // if(!isSucess()) then a message will appear here, or null if success
pack.getException(); // if an exception was thrown, can be null, also will be null if success
pack.writeFile(File file); // write the bytes to a file

```

<br/><br/>
<h3>3 - Detailed use case</h3>
<br/>
a more detailed version is in the Flavour:<br/>

```bash

        
        String iv=Ice.randomIvHex();
        String salt=Ice.randomSalt();

        // Ice with AES CBC PKCS5, PBKDF2 key, 256 key length, 1000 iterations
        //
        // the pack will be:
        //
        // Zip compressed, then
        // Encrypted, then
        // Base64 encoded
        //
        //
        Flavour flavour = new Flavour(
                Ice.CIPHER_AES_CBC_PKCS5Padding
                ,Ice.KEY_PBKDF2WithHmacSHA1
                ,iv
                ,256
                ,1000
                ,Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
                // Task... tasks
                // 
                // you can combine any tasks in any oder, just do not be silly
                // so this, although not efficient is ok:
                // Task.BASE64,Task.ZIP,Task.ENCRYPTION,Task.ZIP,Task.BASE64
                // 
                // but this is silly:
                // Task.BASE64, Task.BASE64, Task.BASE64, Task.BASE64, Task.BASE64
        );
        
        Pack encrypted = 
                Ice
                .with(flavour) // cipher instance and inParameterSpec is created here
                .block("password",salt) // secretKey is created here
                .freeze("Text to encrypt, compress and encode") // set the data
                .pack(); // encryption, compression and encoding performed
        
        // we want to send this over http so:
        String sendString = encrypted.toStringUrlSafe();
        
        // we want to write the result to a file:
        // this is the only time you have to worry about catching an exception

        boolean didWrite=false;
        try {
            File f=new File("/tmp/example_file.txt");
            f.createNewFile();
            didWrite= encrypted.writeFile(f);
        } catch(IOException e){}
        
        // we just want to result in byte[] or string form
        String str = encrypted.toString();
        byte[] bytes = encrypted.toBytes();
        
        //
        //
        //
        //
        //  Now to decrypt the data back to it's original format
        //
        //
        
        Pack decrypted = 
                Ice
                .with(flavour)
                .block("password",salt)
                .freeze(encrypted.toString())
                .unpack();
        // so the only change is 
        // .pack()
        // .unpack()
        
        // The Favour is the same, it will auto reverse the 'Task' order when unpacking
        
        // you can access the decrypted data in the same way by accessing the resul Pack.        
        String strDec = decrypted.toString();
        
        byte[] bytesDec = decrypted.toBytes();
        didWrite=false;
        File f = new File("/tmp/example_file.txt");
        
        try {
            f.createNewFile();
            didWrite = decrypted.writeFile(f);
        } catch(IOException e){}
        
        

```

<br/>
<h3>4 - PGP</h3>
<br/>Ice contains a full PGP implementation (RSA,AES), ICE PGP is not currently compatible with OpenPGP or other PGP imp. (future task)<br/>

```bash

        KeyPair keys = null;
        try {
            keys=Ice.randomRsaKeyPair();
        } catch(Exception e) {}

        Ice.Pop pop = new Ice.Pop(new Ice.Flavour(Ice.Pick.ENCRYPTION), keys.getPrivate());
        Ice.Maker maker = Ice.with(pop, Ice.Pick.ZIP, Ice.Pick.ENCRYPTION, Ice.Pick.BASE64);
        Ice.Pack pack = maker.freeze("data to encrypt").unpack();

        Ice.Pack packed=maker
                .freeze(message)
                .pack();

        if(packed.isSuccess()) {

            Ice.Pack unpacked=maker
                    .freeze(packed.toBytes())
                    .unpack();

            if(unpacked.isSuccess() && unpacked.toString().equals(message)) {
                
                System.out.println("Ice PGP successfully Encrypted and decrypted");
            }
        }

```

<h3>5 - Async use</h3>
<br/>to encrypt:<br/>

```bash
coming soon

```

<h3>6 - Extra features</h3>
<br/>to encrypt:<br/>

```bash
coming soon

```

<br/>
<h2>Updates</h2>
v1.1.022 - Added documentation and comments for developers ease<br/>
v1.1.021 - First open release<br/>
<br/><br/>












