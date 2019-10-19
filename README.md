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
✅ PGP - Pretty Good Privacy<br/>
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
6 - Ice Tray & Cubes (Pooling for Server implementations)<br/>
7 - Useful features<br/>
<br/>
Simplest method are not recommend as it uses defaults for Flavour, iv and salt, however depicts well the ease of use.
<br/>
<h3>1 - Simple use</h3>
<br/>to encrypt:<br/>

```

Pack encrypted = Ice
		.with(new Flavour())
		.freeze("Text or bytes[] to encrypt")
		.block("password")
		.pack();


```
<br/>and then to decrypt:<br/>

```

Pack decrypted = Ice
		.with(new Flavour())
		.freeze("Text or bytes[] to decrypt")
		.block("password")
		.unpack();

```
<br/>
<h3>2 - Result pack useful methods</h3>
<br/>reading the Pack:<br/>

```

Pack pack = Ice.with.....

pack.toString(); // return a string version of the data
pack.toBytes(); // returns the bytes
pack.toStringUrlSafe(); // return a string version of the data safe for http url transport
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

```

        
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
                Ice.CIPHER_AES_GCM_PKCS5Padding
                ,Ice.KEY_PBKDF2WithHmacSHA256
                ,iv
                ,256
                ,1000
                ,Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
                // Pick... tasks
                // 
                // you can combine any tasks in any oder, just do not be silly
                // so this, although not efficient is ok:
                // Pick.BASE64,Pick.ZIP,Pick.ENCRYPTION,Pick.ZIP,Pick.BASE64
                // 
                // but this is silly:
                // Pick.BASE64, Pick.BASE64, Pick.BASE64, Pick.BASE64, Pick.BASE64
		//
		// Keep the order for both encryption (pack()) and decryption (unpack())
		// Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
		// the order will be the same, pack runs left to right, unpack runs from right to left.	
        );
        
        Pack encrypted = 
                Ice
                .with(flavour) // cipher instance and inParameterSpec is created here
                .block("password",salt) // secretKey is created here
                .freeze("Text to encrypt, compress and encode") // set the data
                .pack(); // encryption, compression and encoding performed
        or

        Maker maker =
		Ice
		.with(flavour) // cipher instance and inParameterSpec is created here
		.block("password",salt) // secretKey is created here
		.freeze("Text to encrypt, compress and encode") // set the data

	Pack encrypted = 
        	maker.pack(); // encryption, compression and encoding performed


        // we want to send this over http so:
        String sendString = encrypted.toStringUrlSafe();
        
        // we want to write the result to a file:
        // this is one of the only times you have to worry about catching an exception

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

```

        KeyPair keys = null;
        try {
            keys=Ice.randomRsaKeyPair(Ice.RSA_KEY_1024);
        } catch(Exception e) {
            System.out.println("enc fail on keypair generation");
        }
        
        if(keys!=null) {
            Ice.Pop pop = new Ice.Pop(new Ice.Flavour(Ice.Pick.ENCRYPTION), keys.getPublic());
            Ice.Maker maker = Ice.with(pop, Ice.Pick.ZIP, Ice.Pick.ENCRYPTION, Ice.Pick.BASE64);

            // Ice.publicKeyToString(keys.getPublic());
            // use the above to convert the Public key to string
            
            // Ice.stringToPublicKey(publicKeyString);
            // use the above to create the Public key from the String

            Ice.Pack packed=maker
                    .freeze(message)
                    .pack();
            if(packed.isSuccess()) {
                
                Ice.Pop popServer = new Ice.Pop(new Ice.Flavour(Ice.Pick.ENCRYPTION), keys.getPrivate());
                Ice.Maker makerServer = Ice.with(popServer, Ice.Pick.ZIP, Ice.Pick.ENCRYPTION, Ice.Pick.BASE64);
                
                Ice.Pack unpacked=makerServer
                        .freeze(packed.toBytes())
                        .unpack();
                if(unpacked.isSuccess() && unpacked.toString().equals(message)) {

                    System.out.println("Success Ice PGP encryption and decrytion worked");
                } else {
                    System.out.println("dec fail: "+packed.toString());
                    System.out.println("dec fail: "+packed.getMessage());
                    if(packed.getException()!=null) {
                        packed.getException().printStackTrace();
                    }
                }
            } else {
                System.out.println("enc fail: "+packed.getMessage());
                if(packed.getException()!=null) {
                    packed.getException().printStackTrace();
                }
            }
        }

```

<h3>5 - Async use</h3>
<br/>to encrypt:<br/>

```

        String iv=Ice.randomIvHex();
        String salt=Ice.randomSalt();
        String password = Ice.randomString(32);
        
        Flavour flavour = new Flavour(
                Ice.CIPHER_AES_GCM_PKCS5Padding
                ,Ice.KEY_PBKDF2WithHmacSHA256
                ,iv
                ,256
                ,500000
                ,Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
        );
        
        Maker maker = Ice.with(flavour);
        
        
        
        maker.freezePack("Encrypt his text with it's own seperate thread using high iterations so it takes a long time"
                , password
                , salt
                , new Ice.CoolPack() {
                    @Override
                    public void go(Pack pack) {
                        if(pack.isSuccess()) {
                            System.out.println("Ice Async test Encrypt success: "+pack.toString());
                            
                            // now decrypt, usually you would not call this in the Coolpack, but for the test it should be so.

                            System.out.println("Ice unpack");
                            maker.freezeUnpack(pack.toString()
                                    , password
                                    , salt
                                    , new Ice.CoolPack() {
                                        @Override
                                        public void go(Pack pack) {
                                            if(pack.isSuccess()) {
                                                System.out.println("Ice Async Decrypt test success: "+pack.toString());

                                            } else {
                                                System.out.println("Ice Async Decrypt test failed: "+pack.getMessage());
                                                if(pack.getException()!=null) {
                                                    pack.getException().printStackTrace();
                                                }
                                            }
                                        }
                                    });
                            
                            
                            
                        } else {
                            System.out.println("Ice Async Encrypt test failed: "+pack.getMessage());
                            if(pack.getException()!=null) {
                                pack.getException().printStackTrace();
                            }
                        }
                    }
                });


```

<h3>6 - Ice Tray & Cubes</h3>
<br/>Ice pooling for Server implementations, for a full test scenario including multiple Trays and maultiple Threads, see IceTest and the called TestTrayRunner<br/><br/>
Opening and closing a Tray<br/>

```

    String iv=Ice.randomIvHex();
    Flavour flavour = new Flavour(
            Ice.CIPHER_AES_GCM_PKCS5Padding
            ,Ice.KEY_PBKDF2WithHmacSHA256
            ,iv
            ,256
            ,5000
            ,Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
    );
    Ice.Maker maker = Ice.with(flavour);
    int trayId=1;
    try {

        Ice.Tray.open(trayId, maker, 2,true);  // This will open up a tray, with a min of 2 Cubes kept in cache and montioring stats
	// Ice.Tray.open(trayId, maker); // this will open up a Tray with no cache management or stats

    } catch (Ice.Tray.InvalidTrayException ex) {
	// Tray exists already
        ex.printStackTrace();
    }

    // IMPORTANT - on Server shudown always close ALL trays.
    Ice.Tray.close(trayId);
    

```

<br/>Getting an Ice.Cube and using it<br/>

```
    // An Ice.Cube requires password and salt, you cannot change the IV, changing the IV will come in the next version.

    Ice.Cube cube = Ice.Tray.get(trayId);
    String stringToUse = Ice.randomString(5000);
    String salt = Ice.randomSalt();
    String password = Ice.randomString(20);
    
    Ice.Pack pack = cube.block(password,salt).freeze(stringToUse).pack();
    if(pack.isSuccess()) {
	System.out.println("Success on encrypt");

        Ice.Cube ucube = Ice.Tray.get(trayId);
        Ice.Pack unpack=ucube.block(password,salt).freeze(pack.toBytes()).unpack();
        if(unpack.isSuccess()) {
            if(stringToUse.equals(unpack.toString())) {
                System.out.println("Succes on unpack and equals test confirmed correct");
                    
            }
        }
        // After you have finished with the Ice.Cube
        // ALWAYS release it to put it back into the pool.
	ucube.release();
    }

    // After you have finished with the Ice.Cube
    // ALWAYS release it to put it back into the pool.
    cube.release();


```
<br/>
<h3>7 - Useful features</h3>
<br/>Ice also comes with direct access to many of the useful features it depends on<br/><br/>

```
        
        
	Ice.randomIvHex(); // get a secure random hex string
	Ice.randomSalt(); // get a secure random salt string
	Ice.randomString(20); // get a secure random string useful for password gen

	//
	// base 64
	//

	String strToEncode = "How to use Base64";

	String encoded=Ice.Base64.encodeToString(Ice.stringToBytes(strToEncode), Ice.Base64.DEFAULT);

	String decoded=Ice.bytesToString(Ice.Base64.decode(Ice.stringToBytes(encoded), Ice.Base64.DEFAULT));


	//
	// compression
	//

	byte[] zip = Ice.stringToBytes("How to use zip compression");

	try {
	    
	    byte[] zippedBytes=Ice.Zip.zipBytes(zip,"filname.txt");
	    
	    // 
	    // If you want to write the data to disk
	    // 
	    //File f = new File("zipFileName.zip");
	    //f.createNewFile();
	    //Ice.writeBytes(f, zipped);
	    
	    byte[] unzipped=Ice.Zip.unzipBytes(zippedBytes,"filename.txt");
	    
	} catch (IOException ex) {
	    
	}
        
	// String compression
        
	byte[] compressedString = LZ77.pack(Ice.stringToBytes("This version works directly with byte[]"));
	
	byte[] decomressedString = LZ77.unpack(compressedString);
	
        

```

<br/>
<h2>Updates</h2>
v1.1.104 - Replace Hex IV String decoder for more lighweight version, bug fix on salt encoding to byte[] <br/>
v1.1.103 - Changed default AES to GCM No Padding for Android compatability<br/>
v1.1.101 - Ice.Tray pooling finalised<br/>
v1.1.100 - Ice.Tray pooling implemented - Server side implementations<br/>
v1.1.024 - Defaults now set to the security versions AES-GCM, SHA256, Test class expanded.<br/>
v1.1.023 - Small tweaks and opened up RSA key size choice (1024,2048,4096)<br/>
v1.1.022 - Added documentation and comments for developers ease<br/>
v1.1.021 - First open release<br/>
<br/><br/>












