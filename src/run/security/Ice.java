package run.security;


/**
 *
 *     Ice Pack
 *     Inclusive Compression Encryption Pack
 *
 *     Utility for encoding, compressing (and encoding) of byte[] data or Strings... all Inclusive
 *
 *
 *
 */


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;




public class Ice {

    // Recommended to change DEFAULT_IV_HEX and DEFAULT_SALT values if you are using very basic Flavour() instances that do not include specific IV and Salt
    // you can generate new values using:
    // Ice.randomIvHex();
    // Ice.randomSalt();
    //
    // you can also set these manually at runtime, do this on the very startup of system, before any Ice...calls
    // Ice.setDefaultIv(String/byte[]);
    // Ice.setDefaultSalt(String);
    //
    private static String DEFAULT_IV_HEX="DA5CDAB0B296271A8E2E30DC643E6969";
    private static String DEFAULT_SALT="82662731EDC2DBD7E4C576561519817E";




    //
    // other defaults

    private static final int DEFAULT_ITERATIONS=1000;  // 500 = fast, 1000, medium, 5000+ heavy (use CoolPack - callback methods).
    private static final int DEFAULT_KEY_LENGTH=256;  // 128,256,512
    public static final Charset UTF_8= StandardCharsets.UTF_8;
    public static final Charset UTF_16= StandardCharsets.UTF_16;
    public static final Charset US_ASCII= StandardCharsets.US_ASCII;
    public static final Charset ISO_8859_1= StandardCharsets.ISO_8859_1;
    private static Charset DEFAULT_CHARSET=UTF_8;
    public static final int RSA_KEY_1024 = 1024;
    public static final int RSA_KEY_2048 = 2048;
    public static final int RSA_KEY_4096 = 4096;


    // Ciphers and keys
    // add more if wanted, ensure also add to validCiphers & validTasks
    // Ciphers
    public static final String CIPHER_AES_CBC_PKCS5Padding="AES/CBC/PKCS5Padding";
    public static final String CIPHER_AES_ECB_PKCS7Padding= "AES/ECB/PKCS7Padding";
    public static final String CIPHER_AES_CBC_PKCS7Padding= "AES/CBC/PKCS7Padding";
    public static final String CIPHER_AES_OFB_NoPadding= "AES/OFB/NoPadding";
    public static final String CIPHER_AES_CFB_NoPadding= "AES/CFB/NoPadding";
    private static final String DEFAULT_CIPHER=CIPHER_AES_CBC_PKCS5Padding;
    private static final String DEFAULT_ALGORITHM="AES";

    private static final List<String> validCiphers=new ArrayList<>();
    static {
        validCiphers.add(CIPHER_AES_CBC_PKCS5Padding); validCiphers.add(CIPHER_AES_CBC_PKCS7Padding);
        validCiphers.add(CIPHER_AES_ECB_PKCS7Padding); validCiphers.add(CIPHER_AES_OFB_NoPadding);
        validCiphers.add(CIPHER_AES_CFB_NoPadding);
    }

    // Secret Key
    public static final String KEY_PBKDF2WithHmacSHA1="PBKDF2WithHmacSHA1";
    public static final String KEY_PBKDF2WithHmacSHA256="PBKDF2WithHmacSHA256";
    public static final String KEY_PBKDF2WithHmacSHA512="PBKDF2WithHmacSHA512";
    private static final List<String> validKeys=new ArrayList<>();
    static {
        validKeys.add(KEY_PBKDF2WithHmacSHA1);
        validKeys.add(KEY_PBKDF2WithHmacSHA256);
        validKeys.add(KEY_PBKDF2WithHmacSHA512);
    }

    private static final Map<String,Charset> charsets=new HashMap();
    static {
        charsets.put(UTF_8.name(),UTF_8);
        charsets.put(UTF_16.name(),UTF_16);
        charsets.put(US_ASCII.name(),US_ASCII);
        charsets.put(ISO_8859_1.name(),ISO_8859_1);
    }






    // end customisable code area
    // do not change anything below.... there be dragons if you do.




    private Ice() {}
    public enum Pick {
        BASE64
        ,ENCRYPTION
        ,ZIP
        ,LZ77
    }

    public static void addCharset(Charset cs) {
        if(cs!=null)
            charsets.put(cs.name(),cs);
    }
    public static void setDefaultCharset(Charset cs) {
        if(cs!=null) {
            if(!charsets.containsValue(cs))
                charsets.put(cs.name(),cs);
            DEFAULT_CHARSET=cs;
        }
    }
    public static void setDefaultIv(String iv) throws InvalidIvException {
        if(iv==null || !iv.isEmpty())
            throw new InvalidIvException("Cracked Ice default - IV cannot be null or empty");
        byte[] test = Ice.hex(iv);
        if(test==null || test.length==0)
            throw new InvalidIvException("Cracked Ice default - IV error in converting the string IV to hex bytes");
        DEFAULT_IV_HEX=iv;
    }
    public static void setDefaultIv(byte[] iv) throws InvalidIvException {
        if(iv==null || iv.length==0)
            throw new InvalidIvException("Cracked Ice default - IV cannot be null or empty");
        DEFAULT_IV_HEX=bytesToHex(iv);
    }
    public static class InvalidIvException extends Exception {
        public InvalidIvException(String message) { super(message); }
    }
    public static class InvalidSaltException extends Exception {
        public InvalidSaltException(String message) { super(message); }
    }
    public static void setDefaultSalt(String salt) throws InvalidSaltException {
        if(salt==null || salt.isEmpty())
            throw new InvalidSaltException("Cracked Ice default - Salt cannot be null or empty");
        DEFAULT_SALT=salt;
    }
    /*

    Ice.Tray
    The tray is for Server side implementations.
    
     */
    public static class Tray {

        private static final Map<Integer,Shelf> shelfs =new ConcurrentHashMap<>();


        public static class InvalidTrayException extends Exception {
            public InvalidTrayException(String errorMessage) {
                super(errorMessage);
            }
        }

        private static class Shelf {
            private final Maker parentMaker;
            private final int id;

            /*
            
            // Flow monitoring not yet implemented
            
            private final int minFlow;
            private final AtomicLong counter = new AtomicLong(0);
            private final AtomicInteger flowLive = new AtomicInteger(0);  // montior the per current second flow
            private final AtomicInteger flowHistory = new AtomicInteger(0); // monitor the average flow over the life of the shelf
            private final AtomicLong last = new AtomicLong(System.nanoTime()); // last time flow() was called -- using elapsedRealtimeNanos() instead of System.nanoTime()

            private final Thread flow = new Thread() {
                @Override
                public void run() {
                try {
                    wait(1000);
                } catch(Exception e){}
                }
            };
            */
            private SynchronousQueue<Maker> makers=new SynchronousQueue();
            private Shelf(int id, Maker maker, int minFlow)  {
                this.parentMaker=maker;
                this.id=id;

                /*
            
                // Flow monitoring not yet implemented
                // cache no less than 1 second
                if(minFlow<1) {
                    this.minFlow=1;
                } else if(minFlow>60) {
                    this.minFlow=60;
                } else {
                    this.minFlow=minFlow;
                }
                */
            }

            public Cube get() {
                Maker maker = makers.poll();
                if(maker==null) {
                    maker = parentMaker.clone();
                }
                return new Cube(this, id, maker);
            }

        }
        public static void open(int trayId, Maker maker) throws InvalidTrayException {
            open(trayId,maker,2); // default to keep 2 seconds worth in the pipe.
        }
        public static void open(int trayId, Maker maker, int minFlowSeconds) throws InvalidTrayException {
            if(maker==null)
                throw new InvalidTrayException("Cracked Tray: Maker parameter is null");
            if(maker.flavour==null)
                throw new InvalidTrayException("Cracked Tray: Maker has no Flavour");

            if(shelfs.get(trayId)==null) {
                shelfs.put(trayId, new Shelf(trayId, maker,minFlowSeconds));
            } else {
                throw new InvalidTrayException("Cracked Tray: a Tray with already exists with id: "+trayId);
            }
        }
        public static void close(int trayId) {
            // shutdown routine
            shelfs.remove(trayId);
        }
        public static final Cube get(int trayId) {
            Shelf s= shelfs.get(trayId);
            if(s!=null)
                return s.get();
            return null;
        }
    }

    /*
    Ice.Cube

     */
    public static class Cube {
        private final int id;
        private Maker maker;
        private Tray.Shelf shelf;

        private Cube( Tray.Shelf shelf, int id, Maker maker) {
            this.maker=maker;
            this.id=id;
            this.shelf=shelf;
        }
        public synchronized void release() {
            if(maker!=null) {
                shelf.makers.add(maker); // put Maker back into the shelf
                maker = null;  // remove pointer
                shelf = null;  // remove pointer
            }
        }
        public Cube salt(String salt) {
            maker.salt(salt);
            return this;
        }
        public Cube block(String password, String salt) {
            maker.block(password,salt);
            return this;
        }
        public Cube block(String password) {
            maker.block(password);
            return this;
        }
        public Cube freeze(String data) {
            maker.freeze(data);
            return this;
        }
        public Cube freeze(byte[] data) {
            maker.freeze(data);
            return this;
        }
        public Pack pack() {
            return maker.pack();
        }
        public Pack unpack() {
            return maker.unpack();
        }
    }



    /*
    Ice.Pop - PGP implementation 
     */

    private static final byte[] rsaSeperatorBytes=Ice.stringToBytes("\n--DATA\n");

    public static class Pop {
        private final Flavour flavour;
        private final PublicKey usePublicKey;
        private final PrivateKey usePrivateKey;
        /**
         * Constructor for Client side PGP
         * displays when the cursor lingers over the component.
         *
         * @param flavour   the type of encryption to use
         * @param useKey    RSA Public Key received from the Server side (handshake open RSA public key)
         */
        public Pop(Flavour flavour, PublicKey useKey) {
            this.flavour=flavour;
            this.usePublicKey=useKey;
            this.usePrivateKey=null;
        }
        /**
         * Constructor for Server side PGP
         * displays when the cursor lingers over the component.
         *
         * @param flavour   the type of encryption to use
         * @param useKey    RSA Private Key
         */
        public Pop(Flavour flavour, PrivateKey useKey) {
            this.flavour=flavour;
            this.usePrivateKey=useKey;
            this.usePublicKey=null;
        }

        private static class PopPacket {
            private byte[] head;
            private byte[] data;

            private PopPacket(byte[] bytes) {
                int index=0;
                for(int i=0; i<bytes.length; i++) {
                    if(bytes[i]==rsaSeperatorBytes[0]) {
                        if(bytes[i+1]==rsaSeperatorBytes[1]
                            && bytes[i+2]==rsaSeperatorBytes[2]
                            && bytes[i+3]==rsaSeperatorBytes[3]
                            && bytes[i+4]==rsaSeperatorBytes[4]
                            && bytes[i+5]==rsaSeperatorBytes[5]
                            && bytes[i+6]==rsaSeperatorBytes[6]
                        ) {
                            index=i;
                            break;
                        }
                    }
                }
                head=new byte[index];
                data=new byte[bytes.length-rsaSeperatorBytes.length-index];

                System.arraycopy(bytes,0,head,0,index);
                System.arraycopy(bytes,index+rsaSeperatorBytes.length,data,0,bytes.length-index-rsaSeperatorBytes.length);

            }
        }
        /**
         * Encrypt the data for sending to the Server side
         * displays when the cursor lingers over the component.
         *
         * @param bytesToEncrypt   the data to encrypt and send to the server
         */
        private byte[] encrypt(byte[] bytesToEncrypt) throws Exception {
            return IceRSA.encrypt(bytesToEncrypt, usePublicKey);
        }
        /**
         * Decrypt the data received from client side
         * displays when the cursor lingers over the component.
         *
         * @param bytesToDecrypt   the data to decrypt received from the client side
         */
        private String decrypt(byte[] bytesToDecrypt) throws Exception {
            return IceRSA.decrypt(bytesToDecrypt,usePrivateKey);
        }

    }
    /*
    Ice.PopKey
    Simple container class for the RSA keys.
     */
    public static class PopKey {
        private final String privateKey;
        private final String publicKey;

        private PopKey(String publicKey) {
            this.publicKey=publicKey;
            this.privateKey=null;

        }
        private PopKey(String publicKey,String privateKey) {
            this.publicKey=publicKey;
            this.privateKey=privateKey;
        }
        public String getPrivateKey() {
            return privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }
    }


    /*
    Ice.Block
    Class to hold the password and salt data for the AES encryption
     */
    public static class Block {
        public final String password;
        public final String salt;
        /**
         * Create the password block with specified salt value
         *
         * @param password      the password to use
         * @param salt          the salt
         */
        public Block(String password,String salt) {
            this.password =password;
            this.salt= salt;
        }
        /**
         * Create the password block using the default salt value
         *
         * @param password      the password to use
         */
        public Block(String password) {
            this.password = password;
            this.salt= DEFAULT_SALT;
        }
    }

    /*
    Ice.Pack

     */
    public static class Pack {
        private byte[] bytes;
        private boolean success;
        private long time;
        private String message;
        private Exception e;
        private Pack() {  }
        @Override
        public final String toString() {
            if(bytes!=null)
                return bytesToString(bytes);
            return "";
        }
        /**
         * returns the result in a url encoded String for safe transportation across the web
         * 
         * @param charset pass the charset to encode the String with.
         */
        public final String toStringUrlSafe(String charset) throws UnsupportedEncodingException {
            return URLEncoder.encode(toString(), charset);
        }
        /**
         * returns the result in a url encoded String for safe transportation across the web
         */
        public final String toStringUrlSafe() {
            try {
                return URLEncoder.encode(toString(), "UTF-8");
            } catch(Exception e) {}
            return toString();
        }
        public final byte[] toBytes() {
            return bytes;
        }
        public final long getTime() {
            return time;
        }
        public boolean isSuccess() {
            return success;
        }
        /**
         * If isSuccess() returns false, the reason can be viewed here
         */
        public final String getMessage() {
            return message;
        }
        /**
         * If isSuccess() returns false and an exception was thrown, then can see it here, can be null
         */
        public final Exception getException() {
            return e;
        }
        /**
         * write the pack result data to the passed file
         * 
         * @param file the file to write the pack result data to
         */
        public boolean writeFile(File file) throws IOException {
            if(file!=null) {
                if(!file.exists()) {
                    file.createNewFile();
                }
                return writeBytes(file,bytes);
            }
            return false;
        }
    }

    /*
    * Ice.CoolPack = Callback
    * Allows the encryption, decryption, compression, decompression, encding to be done within a seperate Thread with a callback when finished
    *
    */
    public interface CoolPack {
        void go(Pack pack);
    }




    /*
    Ice.Flavour

     */
    public static class Flavour {
        private final String cipher;
        private final String secretKey;
        private final int keyLength;
        private final int iterations;
        private boolean isAes=true;
        private String iv;
        private Pop pgp;

        private final List<Pick> tasks=new ArrayList();
        /**
         * Clone this Flavour
         */
        protected Flavour clone() {
            if(pgp!=null) {
                return new Flavour(pgp, tasks);
            } else {
                return new Flavour(cipher, secretKey, iv, keyLength, iterations, tasks);
            }
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param pgp Ice.Pop is PGP details
         * @param tasks list... of the Ice.Pick tasks to perform.
         */
        public Flavour(Pop pgp, Pick... tasks) {
            this.pgp=pgp;
            this.iv=null;
            this.cipher=null;
            this.secretKey=null;
            this.iterations=0;
            this.keyLength=0;
            addTasks(tasks);
            isAes=false;
        }

        private Flavour(Pop pgp, List<Pick> tasks) {
            this.pgp=pgp;
            //this.pgpKey=pgpKey;
            this.iv=null;
            this.cipher=null;
            this.secretKey=null;
            this.iterations=0;
            this.keyLength=0;
            this.tasks.addAll(tasks);
            isAes=false;
        }

        private Flavour(String CIPHER_, String KEY_, String ivHex, int keyLength, int iterations) {
            this.iv=ivHex;
            this.cipher=CIPHER_;
            this.secretKey=KEY_;
            this.iterations=iterations;
            this.keyLength=keyLength;
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param CIPHER_ Ice.CIPHER_XXXX cipher to use
         * @param KEY_ Ice.KEY_XXXX secret key to use
         * @param ivHex The IV to use with the encryption
         * @param keyLength encryption keyLength
         * @param iterations AES iterations to perform when encrypting, the higher the value the more secure, also the longer the process
         * @param tasks list<> of the Ice.Pick tasks to perform.
         */
        public Flavour(String CIPHER_, String KEY_, String ivHex, int keyLength, int iterations,List<Pick> tasks) {
            this(CIPHER_,KEY_,ivHex,keyLength,iterations);
            this.tasks.addAll(tasks);
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param CIPHER_ Ice.CIPHER_XXXX cipher to use
         * @param KEY_ Ice.KEY_XXXX secret key to use
         * @param ivHex The IV to use with the encryption
         * @param keyLength encryption keyLength
         * @param iterations AES iterations to perform when encrypting, the higher the value the more secure, also the longer the process
         * @param tasks list... of the Ice.Pick tasks to perform.
         */
        public Flavour(String CIPHER_, String KEY_, String ivHex, int keyLength, int iterations, Pick... tasks) {
            this(CIPHER_,KEY_,ivHex,keyLength,iterations);
            addTasks(tasks);
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param CIPHER_ Ice.CIPHER_XXXX cipher to use
         * @param KEY_ Ice.KEY_XXXX secret key to use
         * @param ivHex The IV to use with the encryption
         * @param tasks list... of the Ice.Pick tasks to perform.
         */
        public Flavour(String CIPHER_, String KEY_, String ivHex, Pick... tasks) {
            this(CIPHER_,KEY_,ivHex,DEFAULT_KEY_LENGTH,DEFAULT_ITERATIONS);
            addTasks(tasks);
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param ivHex The IV to use with the encryption
         * @param tasks list... of the Ice.Pick tasks to perform.
         */
        public Flavour(String ivHex, Pick... tasks) {
            this(DEFAULT_CIPHER,KEY_PBKDF2WithHmacSHA1,ivHex,DEFAULT_KEY_LENGTH,DEFAULT_ITERATIONS);
            addTasks(tasks);
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param tasks list... of the Ice.Pick tasks to perform.
         */
        public Flavour(Pick... tasks) {
            this(DEFAULT_CIPHER,KEY_PBKDF2WithHmacSHA1,DEFAULT_IV_HEX,DEFAULT_KEY_LENGTH,DEFAULT_ITERATIONS);
            addTasks(tasks);
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * 
         * @param ivHex The IV to use with the encryption
         */
        public Flavour(String ivHex) {
            this(DEFAULT_CIPHER,KEY_PBKDF2WithHmacSHA1,ivHex,DEFAULT_KEY_LENGTH,DEFAULT_ITERATIONS);
            addTasks(Pick.ENCRYPTION);
        }
        /**
         * Flavour constructor, the Flavour defines the details of any encryption / decryption of data
         * Uses all defaults
         */
        public Flavour() {
            this(DEFAULT_CIPHER,KEY_PBKDF2WithHmacSHA1,DEFAULT_IV_HEX,DEFAULT_KEY_LENGTH,DEFAULT_ITERATIONS);
            addTasks(Pick.ENCRYPTION);
        }
        private void addTasks(Pick... tasks) {
            if(tasks!=null) {
                for (Pick task : tasks) {
                    this.tasks.add(task);
                }
            }
        }
    }

    /**
     * with method creates an Ice Maker with the passed Flavour
     * @param flavour the encryption flavour to use
     */
    public static final Maker with(Flavour flavour)   {
        Maker maker=new Maker(flavour);
        maker.preFreeze();
        return maker;
    }
    /**
     * with method creates an Ice Maker with the passed Flavour
     * @param pgp the PGP Pop flavour to use
     */
    public static final Maker with(Pop pgp, Pick... tasks)   {
        Maker maker=new Maker(new Flavour(pgp, tasks));
        if(maker.flavour.pgp==null) {
            maker.halted=true;
            maker.message="Cracked Ice:  Pop is null";
        }
        return maker;
    }
    /**
     * with method creates an Ice Maker with the default Flavour
     * @param iv The IV to use with the encryption
     * @param password the password to encrypt with
     * @param salt the salt value to use
     * @param tasks list... of the Ice.Pick tasks to perform.
     */
    public static final Maker withBlock(String iv, String password, String salt, Pick... tasks)   {
        Maker maker =null;
        if(password!=null && salt!=null && iv!=null && password.length()>0) {
            maker=new Maker(new Flavour(iv,tasks));
            maker.preFreeze();
            return maker.block(password,salt);
        } else {
            maker=new Maker(new Flavour());
            maker.halted=true;
            maker.message="Cracked Ice:  withBlock encryption password,salt, or iv data is null or empty";
        }
        return maker;
    }

    /**
     * The Maker class, main container class for all the specifics of the Ice process
     */
    public static class Maker {
        private static final int MODE_UNLOCKED=0;
        public static final int MODE_PACK=1;
        public static final int MODE_UNPACK=2;

        private int lockedMode =MODE_UNLOCKED;
        private byte[] cbytes;
        private Flavour flavour;
        private Block block;
        private String salty;

        private Cipher cipher;
        private SecretKey skey;
        private IvParameterSpec ivParameterSpec;

        private boolean halted=false;
        private String message;
        private Exception haltedEx;
        /**
         * The Maker constructor
         */
        private Maker(Flavour flavour) {
            if(flavour==null) {
                halted=true;
                message="Cracked Ice:  Flavour cannot be null";
                return;
            }
            this.flavour=flavour;
            if(flavour.tasks==null || flavour.tasks.isEmpty()) {
                halted=true;
                message="Cracked Ice:  Tasks cannot be null or empty";
                return;
            }
        }
        protected Maker clone() {
            Maker maker = new Maker(flavour.clone());
            maker.block=new Block(block.password,block.salt);
            maker.salty=salty;
            maker.halted=halted;
            maker.message=message;
            maker.haltedEx=haltedEx;
            return maker;
        }
        public boolean isHalted() {
            return halted;
        }
        public String getMessage() {
            return message;
        }
        public boolean isLocked() { return lockedMode!=MODE_UNLOCKED;}
        public boolean lock(int MODE_) {
            if(MODE_==MODE_PACK) {
                lockedMode =MODE_;
            } else {
                lockedMode =MODE_UNPACK;
            }

            preFreeze();
            if(!halted) {
                try {
                    cipher.init(lockedMode, skey, ivParameterSpec);
                    return true;
                } catch (InvalidAlgorithmParameterException e) {
                    halted = true;
                    message = "Cracked Ice:  Cipher: InvalidAlgorithmParameterException = " + e.getMessage();
                    haltedEx = e;
                } catch (InvalidKeyException e) {
                    halted = true;
                    message = "Cracked Ice:  Cipher: InvalidKeyException = " + e.getMessage();
                    haltedEx = e;
                }
            }
            return false;
        }
        private void clearHalted() {
            if(halted) {
                halted = false;
                haltedEx = null;
                message = null;
            }
        }
        /**
         * The Maker block method, the block contain password and salt data
         * 
         * @param password the password to encrypt with
         */
        public final Maker block(String password) {
            if(salty!=null) {
                return block(password,salty);
            }
            return block(new Block(password));
        }
        /**
         * The Maker block method, the block contain password and salt data
         * 
         * @param password the password to encrypt with
         * @param salt the salt to use
         */
        public final Maker block(String password, String salt) {
            return block(new Block(password,salt));
        }
        /**
         * The Maker salt method, adds salt data, allows putting password and salt data in different parts of the system
         * 
         * @param salt the salt to use
         */
        public Maker salt(String salt) {
            salty=salt;
            return this;
        }
        /**
        * drip method, allow adding of iv at any time
        * 
        * @param iv The IV to use with the encryption
        */
        public final Maker drip(String iv) {
            if(flavour!=null && iv!=null) {
                clearHalted();
                flavour.iv=iv;
                preDrip();
            }
            return this;
        }
        private final Maker block(Block block) {
            if(flavour.isAes) {
                clearHalted();
                this.block=block;
                if(this.block==null) {
                    halted=true;
                    message="Cracked Ice:  Block required";
                } else {
                    if(block.password==null || block.password.isEmpty()) {
                        halted=true;
                        message="Cracked Ice:  Password cannot be null or empty";
                    }
                    if(block.salt==null || block.salt.isEmpty()) {
                        halted=true;
                        message="Cracked Ice:  Salt cannot be null or empty";
                    }
                }

                if(!halted) {
                    try {
                        skey = generateKey();
                    } catch (NoSuchAlgorithmException e) {
                        halted=true;
                        message="Cracked Ice:  key: NoSuchAlgorithmException = "+e.getMessage();
                        haltedEx=e;
                    } catch (InvalidKeySpecException e) {
                        halted=true;
                        message="Cracked Ice:  key: InvalidKeySpecException = "+e.getMessage();
                        haltedEx=e;
                    } catch (IllegalStateException e) {
                        halted=true;
                        message="Cracked Ice:  key: IllegalStateException = "+e.getMessage();
                        haltedEx=e;
                    }
                }
            }
            return this;
        }
        /**
         * freezePack method puts all data in and immediately runs the Ice.Maker, once done the pack is passed back with the CoolPack (callback)
         * This method is mainly for long running tasks (high level of encryption / large data)
         * Encryption only
         * 
         * @param cbytes The bytes to encrypt
         * @param password The password
         * @param salt The salt
         * @param callback The callback method to return the Pack result.
         */
        public void freezePack(byte[] cbytes, String password, String salt, CoolPack callback) {
            freezePackRun thread = new freezePackRun(this,cbytes, password, salt, callback);
            thread.start();
        }
        /**
         * freezePack method puts all data in and immediately runs the Ice.Maker, once done the pack is passed back with the CoolPack (callback)
         * This method is mainly for long running tasks (high level of encryption / large data)
         * Encryption only
         * 
         * @param packText the data to encrypt in String form
         * @param password The password
         * @param salt The salt
         * @param callback The callback method to return the Pack result.
         */
        public void freezePack(String packText, String password, String salt, CoolPack callback) {
            freezePackRun thread = new freezePackRun(this,stringToBytes(packText), password, salt, callback);
            thread.start();
        }
        private class freezePackRun extends Thread {
            private Maker maker;
            private byte[] cbytes;
            private String password;
            private String salt;
            private CoolPack callback;
            public freezePackRun(Maker maker, byte[] cbytes, String password, String salt, CoolPack callback) {
                this.maker=maker;
                this.cbytes=cbytes;
                this.password=password;
                this.salt=salt;
                this.callback=callback;
            }
            @Override
            public void run() {
                maker.block(password,salt);
                maker.freeze(cbytes);
                Pack pack = maker.pack();
                if(callback!=null) {
                    callback.go(pack);
                }
            }
        }
        /**
         * freezeUnpackPack method puts all data in and immediately runs the Ice.Maker, once done the pack is passed back with the CoolPack (callback)
         * This method is mainly for long running tasks (high level of encryption / large data)
         * Decryption only
         * 
         * @param packedText the data to decrypt in String form
         * @param password The password
         * @param salt The salt
         * @param callback The callback method to return the Pack result.
         */
        public void freezeUnpack(String packedText, String password,  String salt, CoolPack callback) {
            freezeUnpackRun thread = new freezeUnpackRun(this,stringToBytes(packedText), password, salt, callback);
            thread.start();
        }
        /**
         * freezeUnpackPack method puts all data in and immediately runs the Ice.Maker, once done the pack is passed back with the CoolPack (callback)
         * This method is mainly for long running tasks (high level of encryption / large data)
         * Decryption only
         * 
         * @param packedBytes the data to decrypt in bytes[] form
         * @param password The password
         * @param salt The salt
         * @param callback The callback method to return the Pack result.
         */
        public void freezeUnpack(byte[] packedBytes, String password, String salt, CoolPack callback) {
            freezeUnpackRun thread = new freezeUnpackRun(this,cbytes, password, salt, callback);
            thread.start();
        }
        private class freezeUnpackRun extends Thread {
            private Maker maker;
            private byte[] cbytes;
            private String password;
            private String salt;
            private CoolPack callback;
            public freezeUnpackRun(Maker maker, byte[] cbytes, String password, String salt, CoolPack callback) {
                this.maker=maker;
                this.cbytes=cbytes;
                this.password=password;
                this.salt=salt;
                this.callback=callback;
            }
            @Override
            public void run() {
                maker.block(password,salt);
                maker.freeze(cbytes);
                Pack pack = maker.unpack();
                if(callback!=null) {
                    callback.go(pack);
                }
            }
        }
        private void preDrip() {
            byte[] iv = hex(flavour.iv);
            ivParameterSpec = new IvParameterSpec(iv);
        }
        private void preFreeze() {
            if(flavour.isAes) {
                if (flavour.iv == null || flavour.iv.isEmpty()) {
                    halted = true;
                    message = "Cracked Ice:  iv input cannot be null or empty";
                }
                if (!isValidCipher(flavour.cipher)) {
                    halted = true;
                    message = "Cracked Ice:  not a valid cipher for this version, only use: " + join(", ", validCiphers);
                }
                if (!isValidSecretKey(flavour.secretKey)) {
                    halted = true;
                    message = "Cracked Ice:  not a valid secret key spec for this version, only use: " + join(", ", validKeys);
                }
            }
            if(!halted && flavour.isAes) {

                preDrip();

                try {
                    cipher = Cipher.getInstance(flavour.cipher);
                } catch (NoSuchAlgorithmException e) {
                    halted=true;
                    message="Cracked Ice:  Cipher: NoSuchAlgorithmException = "+e.getMessage();
                    haltedEx=e;
                } catch (NoSuchPaddingException e) {
                    halted=true;
                    message="Cracked Ice:  Cipher: NoSuchPaddingException = "+e.getMessage();
                    haltedEx=e;
                }
            }
        }
        /**
         * freeze method, adds in the data to encrypt / decrypt
         * 
         * @param text the data to encrypt / decrypt
         * @return 
         */
        public final Maker freeze(String text) {
            if(text==null || text.isEmpty()) {
                halted=true;
                message="Cracked Ice:  text input cannot be null or empty";
            }
            return freeze(stringToBytes(text));
        }
        /**
         * freeze method, adds in the data to encrypt / decrypt
         * 
         * @param cbytes the byte data to encrypt / decrypt
         * @return 
         */
        public final Maker freeze(byte[] cbytes) {
            if(cbytes==null || cbytes.length==0) {
                halted=true;
                message="Cracked Ice:  byte[] input cannot be null or empty";
            } else {
                this.cbytes=cbytes;
            }
            return this;
        }
        /**
         * Pack the data (encryption)
         * @return 
         */
        public final Pack pack() {
            return packUnpack(true);
        }
        /**
         * Unpack the data (decryption)
         * @return 
         */
        public final Pack unpack() {
            return packUnpack(false);
        }
        private final Pack packUnpack(boolean doPack) {
            Pack pack = new Pack();
            long started=System.currentTimeMillis();

            if(cbytes==null) {
                halted = true;
                message = "Cracked Ice:  no data to encrypt / decrypt";
            }


            if(!halted) {
                if(lockedMode!=MODE_UNLOCKED)
                    doPack=lockedMode==MODE_PACK?true:false;
                List<Pick> useTasks=null;
                int encMode=Cipher.ENCRYPT_MODE;
                useTasks=new ArrayList<>(flavour.tasks);
                if(!doPack) {
                    encMode=Cipher.DECRYPT_MODE;
                    Collections.reverse(useTasks);
                }
                for(int i=0; i<useTasks.size(); i++) {
                    Pick task= useTasks.get(i);
                    if(!halted) {
                        switch (task) {
                            case BASE64:
                                try {
                                    if(doPack) {
                                        cbytes = Base64.encode(cbytes, Base64.DEFAULT);
                                    } else {
                                        cbytes = Base64.decode(cbytes, Base64.DEFAULT);
                                    }
                                } catch(IllegalArgumentException e) {
                                    halted=true;
                                    message="Cracked Ice:  Base64: IllegalArgumentException = "+e.getMessage();
                                    haltedEx=e;
                                }
                                break;
                            case ENCRYPTION:
                                if(flavour.isAes) {
                                    try {
                                        if(lockedMode==MODE_UNLOCKED) {
                                            cipher.init(encMode, skey, ivParameterSpec);
                                        }
                                        cbytes = cipher.doFinal(cbytes);
                                    } catch (IllegalBlockSizeException e) {
                                        halted = true;
                                        message = "Cracked Ice:  Cipher: IllegalBlockSizeException = " + e.getMessage();
                                        haltedEx = e;
                                    } catch (BadPaddingException e) {
                                        halted = true;
                                        message = "Cracked Ice:  Cipher: BadPaddingException = " + e.getMessage();
                                        haltedEx = e;
                                    } catch (InvalidAlgorithmParameterException e) {
                                        halted = true;
                                        message = "Cracked Ice:  Cipher: InvalidAlgorithmParameterException = " + e.getMessage();
                                        haltedEx = e;
                                    } catch (InvalidKeyException e) {
                                        halted = true;
                                        message = "Cracked Ice:  Cipher: InvalidKeyException = " + e.getMessage();
                                        haltedEx = e;
                                    }

                                } else {
                                    if(encMode==Cipher.ENCRYPT_MODE) {
                                        try {
                                            String password=Ice.randomString(48);
                                            String ivhex=Ice.randomIvHex();
                                            String salt=Ice.randomSalt();
                                            String popDecHead = password+":"+ivhex+":"+salt;
                                            byte[] popDec=flavour.pgp.encrypt(Ice.stringToBytes(popDecHead));
                                            Ice.Pack icePack = Ice.with(flavour.pgp.flavour).drip(ivhex).block(password,salt).freeze(cbytes).pack();
                                            if(icePack.isSuccess()) {
                                                cbytes=icePack.toBytes();
                                                byte[] appended=new byte[cbytes.length+popDec.length+rsaSeperatorBytes.length];
                                                System.arraycopy(popDec,0,appended,0,popDec.length);
                                                System.arraycopy(rsaSeperatorBytes,0,appended,popDec.length,rsaSeperatorBytes.length);
                                                System.arraycopy(cbytes,0,appended,popDec.length+rsaSeperatorBytes.length,cbytes.length);
                                                cbytes=appended;
                                            } else {
                                                halted = true;
                                                message = "Cracked Ice:  PGP - Inner encrypt exception = " + icePack.getMessage();
                                                haltedEx = icePack.getException();
                                            }
                                        } catch(Exception e) {
                                            halted = true;
                                            message = "Cracked Ice:  PGP public encrypt exception = " + e.getMessage();
                                            haltedEx = e;
                                        }
                                    } else {
                                        try {
                                            Pop.PopPacket popPack = new Pop.PopPacket(cbytes);
                                            String decPop = flavour.pgp.decrypt(popPack.head);
                                            if(decPop!=null) {
                                                String[] sp=decPop.split(":");
                                                if(sp!=null && sp.length==3) {
                                                    String password=sp[0];
                                                    String ivhex=sp[1];
                                                    String salt=sp[2];
                                                    Ice.Pack icePack = Ice.with(flavour.pgp.flavour).drip(ivhex).block(password,salt).freeze(popPack.data).unpack();
                                                    if(icePack.isSuccess()) {
                                                        cbytes=icePack.toBytes();
                                                    } else {
                                                        halted = true;
                                                        message = "Cracked Ice:  PGP - inner Flavour encrypt exception = " + icePack.getMessage();
                                                        haltedEx = icePack.getException();
                                                    }
                                                }
                                            }

                                        } catch(Exception e) {
                                            halted = true;
                                            message = "Cracked Ice:  PGP private decrypt exception = " + e.getMessage();
                                            haltedEx = e;
                                        }
                                    }
                                }
                                break;
                            case ZIP:
                                try {
                                    if(doPack) {
                                        cbytes = ZipFile.zipBytes(cbytes,"b");
                                    } else {
                                        cbytes = ZipFile.unzipBytes(cbytes,"b");
                                    }
                                } catch (IOException e) {
                                    halted=true;
                                    message="Cracked Ice:  Zip exception = "+e.getMessage();
                                    haltedEx=e;
                                }
                                break;
                            case LZ77:
                                try {
                                    if (doPack) {
                                        cbytes = LZ77.pack(cbytes);
                                    } else {
                                        cbytes = LZ77.unpack(cbytes);
                                    }
                                } catch (Exception e) {
                                    halted=true;
                                    message="Cracked Ice:  LZ77 exception = "+e.getMessage();
                                    haltedEx=e;
                                }
                                break;
                        }
                    }
                }
            }
            if(!halted) {
                pack.bytes = cbytes;
                if(cbytes!=null && cbytes.length>0) {
                    pack.success = true;
                } else {
                    pack.success=false;
                    pack.message="Cracked Ice:  final: process completed successfully but byte[] result is Zero length. Unknown error";
                }
                cbytes=null;
            } else {
                pack.bytes=new byte[0];
                pack.message=message;
                pack.success=false;
                pack.e=haltedEx;
            }
            pack.time=System.currentTimeMillis()-started;
            return pack;
        }
        private SecretKey generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalStateException {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(flavour.secretKey);
            KeySpec spec = new PBEKeySpec(block.password.toCharArray(), hex(block.salt), flavour.iterations, flavour.keyLength);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), DEFAULT_ALGORITHM);
            return key;
        }
    }





    /*

    CONVERTERS

     */
    
    /**
     * Converts bytes to String using the passed charset 
     * @param bytes the bytes[] to convert to String
     * @param charset the charset to encode the String with
     * @return 
     */
    public static final String bytesToString(byte[] bytes, Charset charset) {
        if(bytes!=null)
            return new String(bytes, charset);
        return null;
    }
    /**
     * Converts bytes to String using the DEFAULT_CHARSET 
     * @param bytes the bytes[] to convert to String
     * @return 
     */
    public static final String bytesToString(byte[] bytes) {
        if(bytes!=null)
            return new String(bytes, DEFAULT_CHARSET);
        return null;
    }
    /**
     * Converts String to bytes using the DEFAULT_CHARSET 
     * @param value the String to convert to bytes[]
     * @return 
     */
    public static final byte[] stringToBytes(String value) {
        if(value!=null)
            return value.getBytes(DEFAULT_CHARSET);
        return null;

    }
    /**
     * Converts String to bytes using the passed charset
     * @param value the String to convert to bytes[]
     * @param charset the charset to encode the String with
     * @return 
     */
    public static final byte[] stringToBytes(String value, Charset charset) {
        if(value!=null)
            return value.getBytes(charset);
        return null;

    }
    public static boolean isValidCipher(String cypherImp) {
        return validCiphers.contains(cypherImp);
    }
    public static boolean isValidSecretKey(String secretKeyImp) {
        return validKeys.contains(secretKeyImp);
    }

    /**
     * Joins a List<String> into one String, convenience method
     * @param delimiter
     * @param elements
     * @return 
     */
    public static String join(String delimiter, List<String> elements) {
        StringBuilder joiner = new StringBuilder();
        for (CharSequence cs: elements) {
            if(joiner.length()!=0)
                joiner.append(delimiter);
            joiner.append(cs);
        }
        return joiner.toString();
    }

    /**
     * Write the passed bytes to a file
     * @param file the file to write to, make sure it exists beforehand
     * @param bytes the byte[] data to write to the file
     * @return
     * @throws IOException 
     */
    public static boolean writeBytes(File file, byte[] bytes) throws IOException {
        FileOutputStream stream = new FileOutputStream(file.getAbsoluteFile());
        stream.write(bytes);
        return true;
    }

    private static final String ALPHABET_FULL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    
    /**
     * Create a random Alphanumeric String of defined length (useful for password generation)
     * @param length
     * @return 
     */
    public static final String randomString(final int length) {
        char[] chars = ALPHABET_FULL.toCharArray();
        StringBuilder builder = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            char c = chars[random.nextInt(chars.length)];
            builder.append(c);
        }
        return builder.toString();
    }
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    /**
     * Convert bytes[] to Hex, useful for iv functions
     * @param bytes
     * @return 
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    /**
     * Create a random IV with a length of 16
     * @return 
     */
    public static String randomIvHex() {
        return randomIvHex(16);
    }
    /**
     * Create a random IV of defined length
     * @param ivSize
     * @return 
     */
    public static String randomIvHex(int ivSize) {
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return bytesToHex(iv);
    }
    /**
     * Creates a random salt with a length of 32
     * @return 
     */
    public static String randomSalt() {
        return randomSalt(32);
    }
    /**
     * Creates a random salt of defined length
     * @param length
     * @return 
     */
    public static String randomSalt(int length) {
        StringBuilder builder = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            char c = hexArray[random.nextInt(hexArray.length)];
            builder.append(c);
        }
        return builder.toString();
    }


    /**
     * Convert a hex String to byte[]
     * @param str
     * @return 
     */
    public static byte[] hex(String str) {
        try {
            return Hex.decode(str);
        }
        catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Generate a random RSA key pair for Ice.Pop PGP
     * @return
     * @param RSA_KEY_ the key size to use
     * @throws Exception 
     */
    public static KeyPair randomRsaKeyPair(int RSA_KEY_) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_KEY_, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }
    /**
     * Generate a random RSA 2058 key pair for Ice.Pop PGP
     * @return
     * @throws Exception 
     */
    public static KeyPair randomRsaKeyPair() throws Exception {
        return randomRsaKeyPair(RSA_KEY_2048);
    }
    private static class IceRSA {
        private static byte[] encrypt(byte[] toEncrypt, PublicKey publicKey) throws Exception {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] cipherText = encryptCipher.doFinal(toEncrypt);

            return cipherText;
        }
        public static String decrypt(byte[] toDecrypt, PrivateKey privateKey) throws Exception {

            Cipher decriptCipher = Cipher.getInstance("RSA");
            decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

            return new String(decriptCipher.doFinal(toDecrypt), DEFAULT_CHARSET);
        }
    }
    /**
     * convert a private key String back to the private Key pair
     * @param key64
     * @return
     * @throws GeneralSecurityException 
     */
    public static PrivateKey stringToPrivateKey(String key64) throws GeneralSecurityException {
        byte[] clear = Base64.decode(key64,Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    /**
     * Convert the public key String back to the public key pair
     * @param stored
     * @return
     * @throws GeneralSecurityException 
     */
    public static PublicKey stringToPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = Base64.decode(stored,Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

    public static String privateKeyToString(PrivateKey priv) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
                PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        String key64 = bytesToString(Base64.encode(packed,Base64.DEFAULT));

        Arrays.fill(packed, (byte) 0);
        return key64;
    }

    /**
     * Converts the public key to a String to send to the client
     * @param publ
     * @return
     * @throws GeneralSecurityException 
     */
    public static String publicKeyToString(PublicKey publ) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = fact.getKeySpec(publ,
                X509EncodedKeySpec.class);
        return bytesToString(Base64.encode(spec.getEncoded(),Base64.DEFAULT));
    }

    public static class ZipFile {
        public static byte[] zipBytes(byte[] input, String filename) throws IOException {
            if(filename==null)
                throw new IOException("Zip filename cannot be null");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            ZipEntry entry = new ZipEntry(filename);
            entry.setSize(input.length);
            zos.putNextEntry(entry);
            zos.write(input);
            zos.closeEntry();
            zos.close();
            byte[] bytes=baos.toByteArray();
            return bytes;
        }
        public static byte[] unzipBytes( byte[] input, String filename) throws IOException {
            byte[] buffer=new byte[1];
            ByteArrayInputStream baos = new ByteArrayInputStream(input);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ZipInputStream zis = new ZipInputStream(baos);
            ZipEntry entry = zis.getNextEntry();
            if (entry != null) {
                while ((zis.read(buffer)) > 0) {
                    out.write(buffer);
                }
            }
            zis.closeEntry();
            zis.close();
            buffer=out.toByteArray();
            out.flush();
            out.close();

            return buffer;
        }
    }
    public static class GzipUtil {

        public static byte[] zip(final String str) {
            if ((str == null) || (str.length() == 0)) {
                throw new IllegalArgumentException("Cannot zip null or empty string");
            }

            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {
                    gzipOutputStream.write(str.getBytes(DEFAULT_CHARSET));
                }
                return byteArrayOutputStream.toByteArray();
            } catch(IOException e) {
                throw new RuntimeException("Failed to zip content", e);
            }
        }

        public static String unzip(final byte[] compressed) {
            if ((compressed == null) || (compressed.length == 0)) {
                throw new IllegalArgumentException("Cannot unzip null or empty bytes");
            }
            if (!isZipped(compressed)) {
                return new String(compressed);
            }

            try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressed)) {
                try (GZIPInputStream gzipInputStream = new GZIPInputStream(byteArrayInputStream)) {
                    try (InputStreamReader inputStreamReader = new InputStreamReader(gzipInputStream, DEFAULT_CHARSET)) {
                        try (BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
                            StringBuilder output = new StringBuilder();
                            String line;
                            while((line = bufferedReader.readLine()) != null){
                                output.append(line);
                            }
                            return output.toString();
                        }
                    }
                }
            } catch(IOException e) {
                throw new RuntimeException("Failed to unzip content", e);
            }
        }

        public static boolean isZipped(final byte[] compressed) {
            return (compressed[0] == (byte) (GZIPInputStream.GZIP_MAGIC)) && (compressed[1] == (byte) (GZIPInputStream.GZIP_MAGIC >> 8));
        }
    }


    /**
     *   getCharset(String)
     *   Probes a String and determines the Charset, see Charset[] charsets for list of available
     *   Modified version adapted from:
     *   https://www.turro.org/publications/?item=114&page=0
     * @param value
     * @return 
     */
    public static Charset getCharset(String value) {
        Charset probe = UTF_8;
        for(Charset charset : charsets.values()) {
            if(value.equals(convert(convert(value, charset, probe), probe, charset))) {
                return charset;
            }

        }
        return UTF_8;
    }
    private static String convert(String value, Charset fromEncoding, Charset toEncoding) {
        return new String(value.getBytes(fromEncoding), toEncoding);
    }


    /*
    Hex converter class by Spongy castle
     */
    public static class EncoderException
            extends IllegalStateException
    {
        private Throwable cause;

        EncoderException(String msg, Throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }
    private static class Hex
    {
        static final Encoder encoder = new HexEncoder();

        public static String toHexString(
                byte[] data)
        {
            return toHexString(data, 0, data.length);
        }

        public static String toHexString(
                byte[] data,
                int    off,
                int    length)
        {
            byte[] encoded = encode(data, off, length);
            return bytesToString(encoded);
        }

        /**
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
        public static byte[] encode(
                byte[]    data)
        {
            return encode(data, 0, data.length);
        }

        /**
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
        public static byte[] encode(
                byte[]    data,
                int       off,
                int       length)
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            try
            {
                encoder.encode(data, off, length, bOut);
            }
            catch (Exception e)
            {
                throw new EncoderException("exception encoding Hex string: " + e.getMessage(), e);
            }

            return bOut.toByteArray();
        }

        /**
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int encode(
                byte[]         data,
                OutputStream   out)
                throws IOException
        {
            return encoder.encode(data, 0, data.length, out);
        }

        /**
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int encode(
                byte[]         data,
                int            off,
                int            length,
                OutputStream   out)
                throws IOException
        {
            return encoder.encode(data, off, length, out);
        }

        /**
         * decode the Hex encoded input data. It is assumed the input data is valid.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] decode(
                byte[]    data)
        {
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();

            try
            {
                encoder.decode(data, 0, data.length, bOut);
            }
            catch (Exception e)
            {
                throw new DecoderException("exception decoding Hex data: " + e.getMessage(), e);
            }

            return bOut.toByteArray();
        }

        /**
         * decode the Hex encoded String data - whitespace will be ignored.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] decode(
                String    data)
        {
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();

            try
            {
                encoder.decode(data, bOut);
            }
            catch (Exception e)
            {
                throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
            }

            return bOut.toByteArray();
        }

        /**
         * decode the Hex encoded String data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
        public static int decode(
                String          data,
                OutputStream    out)
                throws IOException
        {
            return encoder.decode(data, out);
        }
    }


    /*

    HexEncoder

     */
    private interface Encoder
    {
        int encode(byte[] data, int off, int length, OutputStream out) throws IOException;

        int decode(byte[] data, int off, int length, OutputStream out) throws IOException;

        int decode(String data, OutputStream out) throws IOException;
    }
    private static class HexEncoder
            implements Encoder
    {
        protected final byte[] encodingTable =
                {
                        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
                        (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
                };

        /*
         * set up the decoding table.
         */
        protected final byte[] decodingTable = new byte[128];

        protected void initialiseDecodingTable()
        {
            for (int i = 0; i < decodingTable.length; i++)
            {
                decodingTable[i] = (byte)0xff;
            }

            for (int i = 0; i < encodingTable.length; i++)
            {
                decodingTable[encodingTable[i]] = (byte)i;
            }

            decodingTable['A'] = decodingTable['a'];
            decodingTable['B'] = decodingTable['b'];
            decodingTable['C'] = decodingTable['c'];
            decodingTable['D'] = decodingTable['d'];
            decodingTable['E'] = decodingTable['e'];
            decodingTable['F'] = decodingTable['f'];
        }

        public HexEncoder()
        {
            initialiseDecodingTable();
        }

        /**
         * encode the input data producing a Hex output stream.
         *
         * @return the number of bytes produced.
         */
        public int encode(
                byte[]                data,
                int                    off,
                int                    length,
                OutputStream    out)
                throws IOException
        {
            for (int i = off; i < (off + length); i++)
            {
                int    v = data[i] & 0xff;

                out.write(encodingTable[(v >>> 4)]);
                out.write(encodingTable[v & 0xf]);
            }

            return length * 2;
        }

        private boolean ignore(
                char    c)
        {
            return c == '\n' || c =='\r' || c == '\t' || c == ' ';
        }

        /**
         * decode the Hex encoded byte data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
        public int decode(
                byte[]          data,
                int             off,
                int             length,
                OutputStream    out)
                throws IOException
        {
            byte    b1, b2;
            int     outLen = 0;

            int     end = off + length;

            while (end > off)
            {
                if (!ignore((char)data[end - 1]))
                {
                    break;
                }

                end--;
            }

            int i = off;
            while (i < end)
            {
                while (i < end && ignore((char)data[i]))
                {
                    i++;
                }

                b1 = decodingTable[data[i++]];

                while (i < end && ignore((char)data[i]))
                {
                    i++;
                }

                b2 = decodingTable[data[i++]];

                if ((b1 | b2) < 0)
                {
                    throw new IOException("invalid characters encountered in Hex data");
                }

                out.write((b1 << 4) | b2);

                outLen++;
            }

            return outLen;
        }

        /**
         * decode the Hex encoded String data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
        public int decode(
                String          data,
                OutputStream out)
                throws IOException
        {
            byte    b1, b2;
            int     length = 0;

            int     end = data.length();

            while (end > 0)
            {
                if (!ignore(data.charAt(end - 1)))
                {
                    break;
                }

                end--;
            }

            int i = 0;
            while (i < end)
            {
                while (i < end && ignore(data.charAt(i)))
                {
                    i++;
                }

                b1 = decodingTable[data.charAt(i++)];

                while (i < end && ignore(data.charAt(i)))
                {
                    i++;
                }

                b2 = decodingTable[data.charAt(i++)];

                if ((b1 | b2) < 0)
                {
                    throw new IOException("invalid characters encountered in Hex string");
                }

                out.write((b1 << 4) | b2);

                length++;
            }

            return length;
        }
    }


    /*
    Hex translator
     */
    private interface Translator
    {
        /**
         * size of the output block on encoding produced by getDecodedBlockSize()
         * bytes.
         */
        public int getEncodedBlockSize();

        public int encode(byte[] in, int inOff, int length, byte[] out, int outOff);

        /**
         * size of the output block on decoding produced by getEncodedBlockSize()
         * bytes.
         */
        public int getDecodedBlockSize();

        public int decode(byte[] in, int inOff, int length, byte[] out, int outOff);
    }
    private static class HexTranslator
            implements Translator
    {
        private static final byte[]   hexTable =
                {
                        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
                        (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
                };

        /**
         * size of the output block on encoding produced by getDecodedBlockSize()
         * bytes.
         */
        public int getEncodedBlockSize()
        {
            return 2;
        }

        public int encode(
                byte[]  in,
                int     inOff,
                int     length,
                byte[]  out,
                int     outOff)
        {
            for (int i = 0, j = 0; i < length; i++, j += 2)
            {
                out[outOff + j] = hexTable[(in[inOff] >> 4) & 0x0f];
                out[outOff + j + 1] = hexTable[in[inOff] & 0x0f];

                inOff++;
            }

            return length * 2;
        }

        /**
         * size of the output block on decoding produced by getEncodedBlockSize()
         * bytes.
         */
        public int getDecodedBlockSize()
        {
            return 1;
        }

        public int decode(
                byte[]  in,
                int     inOff,
                int     length,
                byte[]  out,
                int     outOff)
        {
            int halfLength = length / 2;
            byte left, right;
            for (int i = 0; i < halfLength; i++)
            {
                left  = in[inOff + i * 2];
                right = in[inOff + i * 2 + 1];

                if (left < (byte)'a')
                {
                    out[outOff] = (byte)((left - '0') << 4);
                }
                else
                {
                    out[outOff] = (byte)((left - 'a' + 10) << 4);
                }
                if (right < (byte)'a')
                {
                    out[outOff] += (byte)(right - '0');
                }
                else
                {
                    out[outOff] += (byte)(right - 'a' + 10);
                }

                outOff++;
            }

            return halfLength;
        }
    }
    private static class DecoderException
            extends IllegalStateException
    {
        private Throwable cause;

        DecoderException(String msg, Throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }





    /*

    Base64
     */

    /**
     * Utilities for encoding and decoding the Base64 representation of
     * binary data.  See RFCs <a
     * href="http://www.ietf.org/rfc/rfc2045.txt">2045</a> and <a
     * href="http://www.ietf.org/rfc/rfc3548.txt">3548</a>.
     */
    public static class Base64 {
        /**
         * Default values for encoder/decoder flags.
         */
        public static final int DEFAULT = 0;
        /**
         * Encoder flag bit to omit the padding '=' characters at the end
         * of the output (if any).
         */
        public static final int NO_PADDING = 1;
        /**
         * Encoder flag bit to omit all line terminators (i.e., the output
         * will be on one long line).
         */
        public static final int NO_WRAP = 2;
        /**
         * Encoder flag bit to indicate lines should be terminated with a
         * CRLF pair instead of just an LF.  Has no effect if {@code
         * NO_WRAP} is specified as well.
         */
        public static final int CRLF = 4;
        /**
         * Encoder/decoder flag bit to indicate using the "URL and
         * filename safe" variant of Base64 (see RFC 3548 section 4) where
         * {@code -} and {@code _} are used in place of {@code +} and
         * {@code /}.
         */
        public static final int URL_SAFE = 8;
        /**
         * Flag to pass to {link Base64OutputStream} to indicate that it
         * should not close the output stream it is wrapping when it
         * itself is closed.
         */
        public static final int NO_CLOSE = 16;
        //  --------------------------------------------------------
        //  shared code
        //  --------------------------------------------------------
        /* package */ static abstract class Coder {
            public byte[] output;
            public int op;
            /**
             * Encode/decode another block of input data.  this.output is
             * provided by the caller, and must be big enough to hold all
             * the coded data.  On exit, this.opwill be set to the length
             * of the coded data.
             *
             * @param finish true if this is the final call to process for
             *        this object.  Will finalize the coder state and
             *        include any final bytes in the output.
             *
             * @return true if the input so far is good; false if some
             *         error has been detected in the input stream..
             */
            public abstract boolean process(byte[] input, int offset, int len, boolean finish);
            /**
             * @return the maximum number of bytes a call to process()
             * could produce for the given number of input bytes.  This may
             * be an overestimate.
             */
            public abstract int maxOutputSize(int len);
        }
        //  --------------------------------------------------------
        //  decoding
        //  --------------------------------------------------------
        /**
         * Decode the Base64-encoded data in input and return the data in
         * a new byte array.
         *
         * <p>The padding '=' characters at the end are considered optional, but
         * if any are present, there must be the correct number of them.
         *
         * @param str    the input String to decode, which is converted to
         *               bytes using the default charset
         * @param flags  controls certain features of the decoded output.
         *               Pass {@code DEFAULT} to decode standard Base64.
         *
         * @throws IllegalArgumentException if the input contains
         * incorrect padding
         */
        public static byte[] decode(String str, int flags) {
            return decode(str.getBytes(), flags);
        }
        /**
         * Decode the Base64-encoded data in input and return the data in
         * a new byte array.
         *
         * <p>The padding '=' characters at the end are considered optional, but
         * if any are present, there must be the correct number of them.
         *
         * @param input the input array to decode
         * @param flags  controls certain features of the decoded output.
         *               Pass {@code DEFAULT} to decode standard Base64.
         *
         * @throws IllegalArgumentException if the input contains
         * incorrect padding
         */
        public static byte[] decode(byte[] input, int flags) {
            return decode(input, 0, input.length, flags);
        }
        /**
         * Decode the Base64-encoded data in input and return the data in
         * a new byte array.
         *
         * <p>The padding '=' characters at the end are considered optional, but
         * if any are present, there must be the correct number of them.
         *
         * @param input  the data to decode
         * @param offset the position within the input array at which to start
         * @param len    the number of bytes of input to decode
         * @param flags  controls certain features of the decoded output.
         *               Pass {@code DEFAULT} to decode standard Base64.
         *
         * @throws IllegalArgumentException if the input contains
         * incorrect padding
         */
        public static byte[] decode(byte[] input, int offset, int len, int flags) {
            // Allocate space for the most data the input could represent.
            // (It could contain less if it contains whitespace, etc.)
            Decoder decoder = new Decoder(flags, new byte[len*3/4]);
            if (!decoder.process(input, offset, len, true)) {
                throw new IllegalArgumentException("Cracked Ice:  base-64");
            }
            // Maybe we got lucky and allocated exactly enough output space.
            if (decoder.op == decoder.output.length) {
                return decoder.output;
            }
            // Need to shorten the array, so allocate a new one of the
            // right size and copy.
            byte[] temp = new byte[decoder.op];
            System.arraycopy(decoder.output, 0, temp, 0, decoder.op);
            return temp;
        }
        /* package */ static class Decoder extends Coder {
            /**
             * Lookup table for turning bytes into their position in the
             * Base64 alphabet.
             */
            private static final int DECODE[] = {
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
                    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
                    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            };
            /**
             * Decode lookup table for the "web safe" variant (RFC 3548
             * sec. 4) where - and _ replace + and /.
             */
            private static final int DECODE_WEBSAFE[] = {
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
                    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
                    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            };
            /** Non-data values in the DECODE arrays. */
            private static final int SKIP = -1;
            private static final int EQUALS = -2;
            /**
             * States 0-3 are reading through the next input tuple.
             * State 4 is having read one '=' and expecting exactly
             * one more.
             * State 5 is expecting no more data or padding characters
             * in the input.
             * State 6 is the error state; an error has been detected
             * in the input and no future input can "fix" it.
             */
            private int state;   // state number (0 to 6)
            private int value;
            final private int[] alphabet;
            public Decoder(int flags, byte[] output) {
                this.output = output;
                alphabet = ((flags & URL_SAFE) == 0) ? DECODE : DECODE_WEBSAFE;
                state = 0;
                value = 0;
            }
            /**
             * @return an overestimate for the number of bytes {@code
             * len} bytes could decode to.
             */
            public int maxOutputSize(int len) {
                return len * 3/4 + 10;
            }
            /**
             * Decode another block of input data.
             *
             * @return true if the state machine is still healthy.  false if
             *         bad base-64 data has been detected in the input stream.
             */
            public boolean process(byte[] input, int offset, int len, boolean finish) {
                if (this.state == 6) return false;
                int p = offset;
                len += offset;
                // Using local variables makes the decoder about 12%
                // faster than if we manipulate the member variables in
                // the loop.  (Even alphabet makes a measurable
                // difference, which is somewhat surprising to me since
                // the member variable is final.)
                int state = this.state;
                int value = this.value;
                int op = 0;
                final byte[] output = this.output;
                final int[] alphabet = this.alphabet;
                while (p < len) {
                    // Try the fast path:  we're starting a new tuple and the
                    // next four bytes of the input stream are all data
                    // bytes.  This corresponds to going through states
                    // 0-1-2-3-0.  We expect to use this method for most of
                    // the data.
                    //
                    // If any of the next four bytes of input are non-data
                    // (whitespace, etc.), value will end up negative.  (All
                    // the non-data values in decode are small negative
                    // numbers, so shifting any of them up and or'ing them
                    // together will result in a value with its top bit set.)
                    //
                    // You can remove this whole block and the output should
                    // be the same, just slower.
                    if (state == 0) {
                        while (p+4 <= len &&
                                (value = ((alphabet[input[p] & 0xff] << 18) |
                                        (alphabet[input[p+1] & 0xff] << 12) |
                                        (alphabet[input[p+2] & 0xff] << 6) |
                                        (alphabet[input[p+3] & 0xff]))) >= 0) {
                            output[op+2] = (byte) value;
                            output[op+1] = (byte) (value >> 8);
                            output[op] = (byte) (value >> 16);
                            op += 3;
                            p += 4;
                        }
                        if (p >= len) break;
                    }
                    // The fast path isn't available -- either we've read a
                    // partial tuple, or the next four input bytes aren't all
                    // data, or whatever.  Fall back to the slower state
                    // machine implementation.
                    int d = alphabet[input[p++] & 0xff];
                    switch (state) {
                        case 0:
                            if (d >= 0) {
                                value = d;
                                ++state;
                            } else if (d != SKIP) {
                                this.state = 6;
                                return false;
                            }
                            break;
                        case 1:
                            if (d >= 0) {
                                value = (value << 6) | d;
                                ++state;
                            } else if (d != SKIP) {
                                this.state = 6;
                                return false;
                            }
                            break;
                        case 2:
                            if (d >= 0) {
                                value = (value << 6) | d;
                                ++state;
                            } else if (d == EQUALS) {
                                // Emit the last (partial) output tuple;
                                // expect exactly one more padding character.
                                output[op++] = (byte) (value >> 4);
                                state = 4;
                            } else if (d != SKIP) {
                                this.state = 6;
                                return false;
                            }
                            break;
                        case 3:
                            if (d >= 0) {
                                // Emit the output triple and return to state 0.
                                value = (value << 6) | d;
                                output[op+2] = (byte) value;
                                output[op+1] = (byte) (value >> 8);
                                output[op] = (byte) (value >> 16);
                                op += 3;
                                state = 0;
                            } else if (d == EQUALS) {
                                // Emit the last (partial) output tuple;
                                // expect no further data or padding characters.
                                output[op+1] = (byte) (value >> 2);
                                output[op] = (byte) (value >> 10);
                                op += 2;
                                state = 5;
                            } else if (d != SKIP) {
                                this.state = 6;
                                return false;
                            }
                            break;
                        case 4:
                            if (d == EQUALS) {
                                ++state;
                            } else if (d != SKIP) {
                                this.state = 6;
                                return false;
                            }
                            break;
                        case 5:
                            if (d != SKIP) {
                                this.state = 6;
                                return false;
                            }
                            break;
                    }
                }
                if (!finish) {
                    // We're out of input, but a future call could provide
                    // more.
                    this.state = state;
                    this.value = value;
                    this.op = op;
                    return true;
                }
                // Done reading input.  Now figure out where we are left in
                // the state machine and finish up.
                switch (state) {
                    case 0:
                        // Output length is a multiple of three.  Fine.
                        break;
                    case 1:
                        // Read one extra input byte, which isn't enough to
                        // make another output byte.  Illegal.
                        this.state = 6;
                        return false;
                    case 2:
                        // Read two extra input bytes, enough to emit 1 more
                        // output byte.  Fine.
                        output[op++] = (byte) (value >> 4);
                        break;
                    case 3:
                        // Read three extra input bytes, enough to emit 2 more
                        // output bytes.  Fine.
                        output[op++] = (byte) (value >> 10);
                        output[op++] = (byte) (value >> 2);
                        break;
                    case 4:
                        // Read one padding '=' when we expected 2.  Illegal.
                        this.state = 6;
                        return false;
                    case 5:
                        // Read all the padding '='s we expected and no more.
                        // Fine.
                        break;
                }
                this.state = state;
                this.op = op;
                return true;
            }
        }
        //  --------------------------------------------------------
        //  encoding
        //  --------------------------------------------------------
        /**
         * Base64-encode the given data and return a newly allocated
         * String with the result.
         *
         * @param input  the data to encode
         * @param flags  controls certain features of the encoded output.
         *               Passing {@code DEFAULT} results in output that
         *               adheres to RFC 2045.
         */
        public static String encodeToString(byte[] input, int flags) {
            try {
                return new String(encode(input, flags), "US-ASCII");
            } catch (UnsupportedEncodingException e) {
                // US-ASCII is guaranteed to be available.
                throw new AssertionError(e);
            }
        }
        /**
         * Base64-encode the given data and return a newly allocated
         * String with the result.
         *
         * @param input  the data to encode
         * @param offset the position within the input array at which to
         *               start
         * @param len    the number of bytes of input to encode
         * @param flags  controls certain features of the encoded output.
         *               Passing {@code DEFAULT} results in output that
         *               adheres to RFC 2045.
         */
        public static String encodeToString(byte[] input, int offset, int len, int flags) {
            try {
                return new String(encode(input, offset, len, flags), "US-ASCII");
            } catch (UnsupportedEncodingException e) {
                // US-ASCII is guaranteed to be available.
                throw new AssertionError(e);
            }
        }
        /**
         * Base64-encode the given data and return a newly allocated
         * byte[] with the result.
         *
         * @param input  the data to encode
         * @param flags  controls certain features of the encoded output.
         *               Passing {@code DEFAULT} results in output that
         *               adheres to RFC 2045.
         */
        public static byte[] encode(byte[] input, int flags) {
            return encode(input, 0, input.length, flags);
        }
        /**
         * Base64-encode the given data and return a newly allocated
         * byte[] with the result.
         *
         * @param input  the data to encode
         * @param offset the position within the input array at which to
         *               start
         * @param len    the number of bytes of input to encode
         * @param flags  controls certain features of the encoded output.
         *               Passing {@code DEFAULT} results in output that
         *               adheres to RFC 2045.
         */
        public static byte[] encode(byte[] input, int offset, int len, int flags) {
            Encoder encoder = new Encoder(flags, null);
            // Compute the exact length of the array we will produce.
            int output_len = len / 3 * 4;
            // Account for the tail of the data and the padding bytes, if any.
            if (encoder.do_padding) {
                if (len % 3 > 0) {
                    output_len += 4;
                }
            } else {
                switch (len % 3) {
                    case 0: break;
                    case 1: output_len += 2; break;
                    case 2: output_len += 3; break;
                }
            }
            // Account for the newlines, if any.
            if (encoder.do_newline && len > 0) {
                output_len += (((len-1) / (3 * Encoder.LINE_GROUPS)) + 1) *
                        (encoder.do_cr ? 2 : 1);
            }
            encoder.output = new byte[output_len];
            encoder.process(input, offset, len, true);
            assert encoder.op == output_len;
            return encoder.output;
        }
        /* package */ static class Encoder extends Coder {
            /**
             * Emit a new line every this many output tuples.  Corresponds to
             * a 76-character line length (the maximum allowable according to
             * <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045</a>).
             */
            public static final int LINE_GROUPS = 19;
            /**
             * Lookup table for turning Base64 alphabet positions (6 bits)
             * into output bytes.
             */
            private static final byte ENCODE[] = {
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
            };
            /**
             * Lookup table for turning Base64 alphabet positions (6 bits)
             * into output bytes.
             */
            private static final byte ENCODE_WEBSAFE[] = {
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
            };
            final private byte[] tail;
            /* package */ int tailLen;
            private int count;
            final public boolean do_padding;
            final public boolean do_newline;
            final public boolean do_cr;
            final private byte[] alphabet;
            public Encoder(int flags, byte[] output) {
                this.output = output;
                do_padding = (flags & NO_PADDING) == 0;
                do_newline = (flags & NO_WRAP) == 0;
                do_cr = (flags & CRLF) != 0;
                alphabet = ((flags & URL_SAFE) == 0) ? ENCODE : ENCODE_WEBSAFE;
                tail = new byte[2];
                tailLen = 0;
                count = do_newline ? LINE_GROUPS : -1;
            }
            /**
             * @return an overestimate for the number of bytes {@code
             * len} bytes could encode to.
             */
            public int maxOutputSize(int len) {
                return len * 8/5 + 10;
            }
            public boolean process(byte[] input, int offset, int len, boolean finish) {
                // Using local variables makes the encoder about 9% faster.
                final byte[] alphabet = this.alphabet;
                final byte[] output = this.output;
                int op = 0;
                int count = this.count;
                int p = offset;
                len += offset;
                int v = -1;
                // First we need to concatenate the tail of the previous call
                // with any input bytes available now and see if we can empty
                // the tail.
                switch (tailLen) {
                    case 0:
                        // There was no tail.
                        break;
                    case 1:
                        if (p+2 <= len) {
                            // A 1-byte tail with at least 2 bytes of
                            // input available now.
                            v = ((tail[0] & 0xff) << 16) |
                                    ((input[p++] & 0xff) << 8) |
                                    (input[p++] & 0xff);
                            tailLen = 0;
                        };
                        break;
                    case 2:
                        if (p+1 <= len) {
                            // A 2-byte tail with at least 1 byte of input.
                            v = ((tail[0] & 0xff) << 16) |
                                    ((tail[1] & 0xff) << 8) |
                                    (input[p++] & 0xff);
                            tailLen = 0;
                        }
                        break;
                }
                if (v != -1) {
                    output[op++] = alphabet[(v >> 18) & 0x3f];
                    output[op++] = alphabet[(v >> 12) & 0x3f];
                    output[op++] = alphabet[(v >> 6) & 0x3f];
                    output[op++] = alphabet[v & 0x3f];
                    if (--count == 0) {
                        if (do_cr) output[op++] = '\r';
                        output[op++] = '\n';
                        count = LINE_GROUPS;
                    }
                }
                // At this point either there is no tail, or there are fewer
                // than 3 bytes of input available.
                // The main loop, turning 3 input bytes into 4 output bytes on
                // each iteration.
                while (p+3 <= len) {
                    v = ((input[p] & 0xff) << 16) |
                            ((input[p+1] & 0xff) << 8) |
                            (input[p+2] & 0xff);
                    output[op] = alphabet[(v >> 18) & 0x3f];
                    output[op+1] = alphabet[(v >> 12) & 0x3f];
                    output[op+2] = alphabet[(v >> 6) & 0x3f];
                    output[op+3] = alphabet[v & 0x3f];
                    p += 3;
                    op += 4;
                    if (--count == 0) {
                        if (do_cr) output[op++] = '\r';
                        output[op++] = '\n';
                        count = LINE_GROUPS;
                    }
                }
                if (finish) {
                    // Finish up the tail of the input.  Note that we need to
                    // consume any bytes in tail before any bytes
                    // remaining in input; there should be at most two bytes
                    // total.
                    if (p-tailLen == len-1) {
                        int t = 0;
                        v = ((tailLen > 0 ? tail[t++] : input[p++]) & 0xff) << 4;
                        tailLen -= t;
                        output[op++] = alphabet[(v >> 6) & 0x3f];
                        output[op++] = alphabet[v & 0x3f];
                        if (do_padding) {
                            output[op++] = '=';
                            output[op++] = '=';
                        }
                        if (do_newline) {
                            if (do_cr) output[op++] = '\r';
                            output[op++] = '\n';
                        }
                    } else if (p-tailLen == len-2) {
                        int t = 0;
                        v = (((tailLen > 1 ? tail[t++] : input[p++]) & 0xff) << 10) |
                                (((tailLen > 0 ? tail[t++] : input[p++]) & 0xff) << 2);
                        tailLen -= t;
                        output[op++] = alphabet[(v >> 12) & 0x3f];
                        output[op++] = alphabet[(v >> 6) & 0x3f];
                        output[op++] = alphabet[v & 0x3f];
                        if (do_padding) {
                            output[op++] = '=';
                        }
                        if (do_newline) {
                            if (do_cr) output[op++] = '\r';
                            output[op++] = '\n';
                        }
                    } else if (do_newline && op > 0 && count != LINE_GROUPS) {
                        if (do_cr) output[op++] = '\r';
                        output[op++] = '\n';
                    }
                    assert tailLen == 0;
                    assert p == len;
                } else {
                    // Save the leftovers in tail to be consumed on the next
                    // call to encodeInternal.
                    if (p == len-1) {
                        tail[tailLen++] = input[p];
                    } else if (p == len-2) {
                        tail[tailLen++] = input[p];
                        tail[tailLen++] = input[p+1];
                    }
                }
                this.op = op;
                this.count = count;
                return true;
            }
        }

        private Base64() { }   // don't instantiate
    }



    /*
        LZ77

        Modified version to be intuitive and have single byte array input/output

        original taken from:

        A simple LZ77 implementation with a 64k search window. (c)2013 mumart@gmail.com
        The output consists of token bytes optionally followed by literals.
            0xxxxxxx                   : Offset 0, length X.
            1xxxxxxx yyyyyyyy yyyyyyyy : Offset Y, length X.
        When offset is zero, length is the number of bytes to be copied from the input.
        When offset is positive, length bytes are to be copied from the output.
    */

    public static byte[] trim(byte[] bytes)    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)        {
            --i;
        }
        return Arrays.copyOf(bytes, i + 1);
    }
    public static class LZ77 {
        // Returns output length.
        public static byte[] pack( byte[] input ) throws Exception{
            int inputLen=input.length;
            byte[] output=new byte[input.length*2];
            int[] index = new int[ 65536 ];
            int[] chain = new int[ 65536 ];
            int inputIdx = 0, outputIdx = 0, literals = 0;
            while( inputIdx < inputLen ) {
                int matchOffset = 0, matchLength = 1;
                // Indexed search. Requires 512k of memory.
                if( inputIdx + 3 < inputLen ) {
                    int key = ( input[ inputIdx ] & 0xFF ) * 33 + ( input[ inputIdx + 1 ] & 0xFF );
                    key = key * 33 + ( input[ inputIdx + 2 ] & 0xFF );
                    key = key * 33 + ( input[ inputIdx + 3 ] & 0xFF );
                    int searchIdx = index[ key & 0xFFFF ] - 1;
                    while( ( inputIdx - searchIdx ) < 65536 && searchIdx >= 0 ) {
                        if( inputIdx + matchLength < inputLen && input[ inputIdx + matchLength ] == input[ searchIdx + matchLength ] ) {
                            int len = 0;
                            while( inputIdx + len < inputLen && len < 127 && input[ searchIdx + len ] == input[ inputIdx + len ] ) {
                                len++;
                            }
                            if( len > matchLength ) {
                                matchOffset = inputIdx - searchIdx;
                                matchLength = len;
                                if( len >= 127 ) {
                                    break;
                                }
                            }
                        }
                        searchIdx = chain[ searchIdx & 0xFFFF ] - 1;
                    }
                    if( matchLength < 4 ) {
                        matchOffset = 0;
                        matchLength = 1;
                    }
                    int idx = inputIdx;
                    int end = inputIdx + matchLength;
                    if( end + 3 > inputLen ) {
                        end = inputLen - 3;
                    }
                    while( idx < end ) {
                        // Update the index for each byte of the input to be encoded.
                        key = ( input[ idx ] & 0xFF ) * 33 + ( input[ idx + 1 ] & 0xFF );
                        key = key * 33 + ( input[ idx + 2 ] & 0xFF );
                        key = key * 33 + ( input[ idx + 3 ] & 0xFF );
                        chain[ idx & 0xFFFF ] = index[ key & 0xFFFF ];
                        index[ key & 0xFFFF ] = idx + 1;
                        idx++;
                    }
                }
                if( matchOffset == 0 ) {
                    literals += matchLength;
                    inputIdx += matchLength;
                }
                if( literals > 0 ) {
                    // Flush literals if match found, end of input, or longest encodable run.
                    if( matchOffset > 0 || inputIdx == inputLen || literals == 127 ) {
                        output[ outputIdx++ ] = ( byte ) literals;
                        int literalIdx = inputIdx - literals;
                        while( literalIdx < inputIdx ) {
                            output[ outputIdx++ ] = input[ literalIdx++ ];
                        }
                        literals = 0;
                    }
                }
                if( matchOffset > 0 ) {
                    //System.out.println( "Offset " + matchOffset + " Length " + matchLength );
                    output[ outputIdx++ ] = ( byte ) ( 0x80 | matchLength );
                    output[ outputIdx++ ] = ( byte ) ( matchOffset >> 8 );
                    output[ outputIdx++ ] = ( byte ) matchOffset;
                    inputIdx += matchLength;
                }
            }
            return trim(output);
            //return outputIdx;
        }

        // Output may be null to calculate uncompressed length.
        public static byte[] unpack( byte[] input) throws Exception {
            int inputLen=input.length;
            byte[] output=new byte[input.length*2];  // L277 cannot compress more than 50%
            int inputIdx = 0, outputIdx = 0;
            while( inputIdx < inputLen ) {
                int matchOffset = 0;
                int matchLength = input[ inputIdx++ ] & 0xFF;
                if( matchLength > 127 ) {
                    matchLength = matchLength & 0x7F;
                    matchOffset = input[ inputIdx++ ] & 0xFF;
                    matchOffset = ( matchOffset << 8 ) | ( input[ inputIdx++ ] & 0xFF );
                }
                if( output == null ) {
                    outputIdx += matchLength;
                    if( matchOffset == 0 ) {
                        inputIdx += matchLength;
                    }
                } else {
                    int outputEnd = outputIdx + matchLength;
                    if( matchOffset == 0 ) {
                        while( outputIdx < outputEnd ) {
                            output[ outputIdx++ ] = input[ inputIdx++ ];
                        }
                    } else {
                        while( outputIdx < outputEnd ) {
                            output[ outputIdx ] = output[ outputIdx - matchOffset ];
                            outputIdx++;
                        }
                    }
                }
            }
            return trim(output);
        }

    }

}