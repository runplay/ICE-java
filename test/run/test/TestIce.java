/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package run.test;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import run.security.Ice;
import run.security.Ice.Flavour;
import run.security.Ice.Maker;
import run.security.Ice.Pack;
import run.security.Ice.Pick;


/**
 *
 * @author coops
 */
public class TestIce {
    
    
    public static void main(String[] args) {
        
        iceQuickTest();
        iceTestDetailed();
        iceTestPGP();
        //iceAsyncTest();
        //iceTestTray();
    }
    
    
    public static void iceTestPGP() {
        System.out.println("\n\nTEST ICE PGP\n\n*****************************************************\nSTART:\n");
        KeyPair keys = null;
        try {
            keys=Ice.randomRsaKeyPair(Ice.RSA_KEY_1024);
        } catch(Exception e) {
            System.out.println("fail on keypair generation");
        }

        String message=Ice.randomString(300);
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
                if(unpacked.isSuccess()) {
                    System.out.println("Ice PGP test success");
                    if(unpacked.toString().equals(message)) {
                        System.out.println("Ice PGP test decrypted equals test confirmed Good data");
                    }
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
    }

    public static void iceAsyncTest() {
        System.out.println("\n\nTEST ICE ASYNC\n\n*****************************************************\nSTART:\n");
        String iv=Ice.randomIvHex();
        String salt=Ice.randomSalt();
        String password = Ice.randomString(32);
        
        Flavour flavour = new Flavour(
                Ice.CIPHER_AES_CBC_PKCS5Padding
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
                            
                            // now decrypt, usually you would not call this in the Coolpack as it is a seperate process, but for the test it should be so.

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
        
        
        System.out.println("Ice end of method, Async data will appear once completed\n\n");
    }
    
    public static void iceQuickTest() {
        
        System.out.println("\n\nTEST ICE QUICK\n\n*****************************************************\nSTART:\n");
        String originalString="Text to Encrypt with a basic Flavour that uses all defaults.";
        byte[] originalBytes = Ice.stringToBytes(originalString);
        
        // Encrypt bytes or string
        Pack encrypted = Ice
			.with(new Flavour())
			.freeze(originalString)
                        .block("password")
			.pack();
        Pack encryptedFromBytes = Ice
			.with(new Flavour())
                        .block("password")
			.freeze(originalBytes)
			.pack();
        
        // Decrypt bytes or string
        Pack decrypted = Ice
			.with(new Flavour())
                        .block("password")
			.freeze(encrypted.toString())
			.unpack();
        Pack decryptedFromBytes = Ice
			.with(new Flavour())
                        .block("password")
			.freeze(encrypted.toBytes())
			.unpack();
        
        Pack pack = encrypted; //Ice.with.....

        // read and use the Pack
        //
        pack.toString(); // return a string version of the data 
        pack.toBytes(); // returns the bytes
        pack.toStringUrlSafe(); // return a string version of the data safe for http transport
        pack.getTime(); // time taken in millis
        pack.isSuccess(); // did the pack succeed
        pack.getMessage(); // if(!isSucess()) then a message will appear here, or null if success
        pack.getException(); // if an exception was thrown, can be null, also will be null if success
        try {
            pack.writeFile(new File("file.txt")); // write the bytes to a file
        } catch(IOException e){}
        
        
    }
    public static void iceTestDetailed() {      
        
        System.out.println("\n\nTEST ICE DETAILED\n\n*****************************************************\nSTART:\n");
        String iv=Ice.randomIvHex();
        String salt=Ice.randomSalt();
        String messageToEncrypt="Text to encrypt, compress and encode";

        // Ice with AES CBC PKCS5, PBKDF2 key, 256 key length, 1000 iterations
        //
        // the pack will be:
        //
        // Zip compressed, then
        // Encrypted, then
        // Base64 encoded
        //
        //
        /*
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
                // so this is ok:
                // Task.BASE64,Task.ZIP,Task.ENCRYPTION,Task.ZIP,Task.BASE64
                // 
                // but this is silly:
                // Task.BASE64, Task.BASE64, Task.BASE64, Task.BASE64, Task.BASE64
        );
        
        Flavour flavour = new Flavour(
                Ice.CIPHER_AES_GCM_NoPadding
                ,Ice.KEY_PBKDF2WithHmacSHA1
                ,iv
                ,256
                ,1000
                ,Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
        );
        
        */
        Flavour flavour = new Flavour(
                Ice.CIPHER_AES_GCM_PKCS5Padding
                ,Ice.KEY_PBKDF2WithHmacSHA256
                ,iv
                ,256
                ,1000
                ,Pick.ZIP,Pick.ENCRYPTION,Pick.BASE64
        );
        Pack encrypted = 
                Ice
                .with(flavour) // cipher instance and inParameterSpec is created here
                .block("password",salt) // secretKey is created here
                .freeze(messageToEncrypt) // set the data
                .pack(); // encryption, compression and encoding performed
        if(encrypted.isSuccess()) {
            System.out.println("Detailed test Encrypted Success");
        } else {
            System.out.println("Detailed test Encrypted Failed: "+encrypted.getMessage());
            if(encrypted.getException()!=null) {
                encrypted.getException().printStackTrace();
            }
        }
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
        if(decrypted.isSuccess()) {
            System.out.println("Detailed test decrypted Success");
            if(messageToEncrypt.equals(decrypted.toString())) {
                System.out.println("Detailed test decrypted equals test confirmed Good data");
            } else {
                System.out.println("Detailed test decrypted equals test Failed bad data");
            }
        } else {
            System.out.println("Detailed test decrypted Failed: "+decrypted.getMessage());
            if(decrypted.getException()!=null) {
                decrypted.getException().printStackTrace();
            }
        }
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
        
        
        
        //
        // Utilites
        //
        
        Ice.randomIvHex(); // get a secure random hex string
        Ice.randomSalt(); // get a secure random salt string
        
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
            Logger.getLogger(TestIce.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        
        
        


        
    }

    /*
    private static final int THREAD_INSTANCE=10;
    private static final int THREAD_LOOP=20;
    private static final int TRAY_INSTANCES=2;
    */

    
    private static final int THREAD_INSTANCE=5;
    private static final int TRAY_INSTANCES=2;
    public static void iceTestTray() {

        System.out.println("\n\nTEST ICE TRAY - thread runner\n\n*****************************************************\nSTART:\n");
        for(int t=0; t<TRAY_INSTANCES; t++) {
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

            try {
                Ice.Tray.open(t, maker, 2,false);
                for(int ti=0; ti<THREAD_INSTANCE; ti++) {
                    TestTrayRunner tmp=new TestTrayRunner(t,ti);
                    tmp.start();
                }
            } catch (Ice.Tray.InvalidTrayException ex) {
                ex.printStackTrace();
            }

        }

    }


}
