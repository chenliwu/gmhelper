package org.zz.gmhelper.test;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM3Util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SM3UtilTest extends GMBaseTest {
    @Test
    public void testHashAndVerify() {
        try {
            byte[] hash = SM3Util.hash(SRC_DATA);
            System.out.println("SM3 hash result:\n" + ByteUtils.toHexString(hash));
            boolean flag = SM3Util.verify(SRC_DATA, hash);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testHashAndVerify1() {
        try {
            String data = "chenlw";
            byte[] hash = SM3Util.hash(data.getBytes(StandardCharsets.UTF_8.name()));
            System.out.println("hash:" + Arrays.toString(hash));
            System.out.println("SM3 hash HexString:\n" + ByteUtils.toHexString(hash));
            String hashBase64String = Base64.toBase64String(hash);
            System.out.println("SM3 Base64 String:\n" + hashBase64String);
            System.out.println("hash:\n" + Arrays.toString(Base64.decode(hashBase64String)));
            boolean flag = SM3Util.verify(data.getBytes(StandardCharsets.UTF_8.name()), hash);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testHmacSM3() {
        try {
            byte[] hmacKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
            byte[] hmac = SM3Util.hmac(hmacKey, SRC_DATA);
            System.out.println("SM3 hash result:\n" + Arrays.toString(hmac));
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
