/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package run.test;

import java.util.ArrayList;
import java.util.List;
import run.security.Ice;

/**
 *
 * @author coops
 */
public class TestTrayRunner extends Thread {

    public static final int THREAD_LOOP=250;

    private StringBuilder sb;
    private List<Boolean> finishedThreads;


    private int trayId;
    private int threadInstance;
    private int countEncryption=0;
    private int countDecryption=0;
    private int countEncryptionFail=0;
    private int countDecryptionFail=0;
    private Object waitObject = new Object();

    public TestTrayRunner(int trayId, int threadInstance) {
        this.trayId=trayId;
        this.threadInstance=threadInstance;
    }

    @Override
    public void run() {
        sb=new StringBuilder();
        finishedThreads=new ArrayList();
        long started=System.currentTimeMillis();
        for(int i=0; i<THREAD_LOOP; i++) {
            Ice.Cube cube = Ice.Tray.get(trayId);
            String stringToUse = Ice.randomString(getRandom(500,5000));
            String salt = Ice.randomSalt();
            String password = Ice.randomString(20);
            
            Ice.Pack pack = cube.block(password,salt).freeze(stringToUse).pack();
            if(pack.isSuccess()) {
                Ice.Cube ucube = Ice.Tray.get(trayId);
                Ice.Pack unpack=ucube.block(password,salt).freeze(pack.toBytes()).unpack();
                if(unpack.isSuccess()) {
                    if(stringToUse.equals(unpack.toString())) {
                        sb.append("\ntrayId: "+trayId+" - thread: "+threadInstance+" - loop: "+i+" - str length: "+stringToUse.length()+" - Completed successfully and equals tested OK");
                            
                    } else {
                        sb.append("\ntrayId: "+trayId+" - thread: "+threadInstance+" - loop: "+i+" Completed successfully BUT equals test FAILED");
                    }
                } else {
                    sb.append("\ntrayId: "+trayId+" - thread: "+threadInstance+" - loop: "+i+" unpack FAILED: "+unpack.getMessage());
                }
                // REMEBER !!!
                // always call release to put back into the pool
                ucube.release();
                //sb.append("\ntrayId: "+trayId+" - thread: "+threadInstance+" - loop: "+i+" Completed successfully");
            } else {
                sb.append("\ntrayId: "+trayId+" - thread: "+threadInstance+" - loop: "+i+" pack FAILED: "+pack.getMessage());
            }
            // REMEBER !!!
            // always call release to put back into the pool, this instance purposely delayed from release till after unpack version
            cube.release();
            
            //System.out.println("trayId: "+trayId+" - size: "+Ice.Tray.size(trayId));

            try {
                if(i>100) {
                    // after 100 iterations slow down the speed (used this to test minCache feature)
                    TestTrayRunner.sleep(getRandom(1500,2500));
                } else {
                    TestTrayRunner.sleep(getRandom(100,200));
                }
            } catch(Exception e) {}

        }
        
        System.out.println(sb.toString());
        TestIce.checkShutdown();
    }

    public static int getRandom(int min, int max) {
        int rand = Double.valueOf(((max+1-min)*Math.random())+min).intValue();
        if(rand>max)
            rand=max;
        return rand;
    }
}
