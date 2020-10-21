package org.zz.gmhelper.test;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM4Util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SM4UtilTest extends GMBaseTest {

    @Test
    public void testEncryptAndDecrypt() {
        try {
            byte[] key = SM4Util.generateKey();
            byte[] iv = SM4Util.generateKey();
            byte[] cipherText = null;
            byte[] decryptedData = null;

            System.out.println("Key:" + Arrays.toString(key));
            System.out.println("iv:" + Arrays.toString(iv));
            System.out.println();

            System.out.println("Key Base64 String:" + Base64.toBase64String(key));
            System.out.println("Iv Base64 String:" + Base64.toBase64String(iv));
            System.out.println();

            String keyHexString = ByteUtils.toHexString(key);
            String ivHexString = ByteUtils.toHexString(iv);
            System.out.println("Key HexString:" + keyHexString + "----length:" + keyHexString.length());
            System.out.println("Iv HexString:" + ivHexString + "----length:" + ivHexString.length());
            System.out.println();

            cipherText = SM4Util.encrypt_ECB_NoPadding(key, SRC_DATA_16B);
            System.out.println("SM4 ECB NoPadding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_ECB_NoPadding(key, cipherText);
            System.out.println("SM4 ECB NoPadding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_16B)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_ECB_Padding(key, SRC_DATA);
            System.out.println("SM4 ECB Padding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_ECB_Padding(key, cipherText);
            System.out.println("SM4 ECB Padding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_CBC_Padding(key, iv, SRC_DATA);
            System.out.println("SM4 CBC Padding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_CBC_Padding(key, iv, cipherText);
            System.out.println("SM4 CBC Padding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_CBC_NoPadding(key, iv, SRC_DATA_16B);
            System.out.println("SM4 CBC NoPadding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_CBC_NoPadding(key, iv, cipherText);
            System.out.println("SM4 CBC NoPadding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_16B)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testCustomKeySM4ECB() throws Exception {
        String charset = StandardCharsets.UTF_8.name();
        // SM4密钥长度分组长度128bit，因此密匙长度为16
        String myKey = "1234567812345678";
        String data = "bytter2020";
        byte[] myKeyBytes = myKey.getBytes(charset);
        byte[] encryptedBytes = SM4Util.encrypt_ECB_Padding(myKeyBytes, data.getBytes(charset));
        String encryptedHexString = ByteUtils.toHexString(encryptedBytes);
        System.out.println("ECB加密后的数据HexString：" + encryptedHexString);
        byte[] decryptedBytes = SM4Util.decrypt_ECB_Padding(myKeyBytes, ByteUtils.fromHexString(encryptedHexString));
        System.out.println("ECB解密后的数据：" + new String(decryptedBytes, charset));
    }

    @Test
    public void testCustomKeySM4CBC() throws Exception {
        String charset = StandardCharsets.UTF_8.name();
        // SM4密钥长度分组长度128bit，因此密匙长度为16
        String myKey = "1234567812345678";
        String myIv = "8765432187654321";
        String data = "bytter2020";
        byte[] myKeyBytes = myKey.getBytes(charset);
        byte[] myIvBytes = myIv.getBytes(charset);
        byte[] encryptedBytes = SM4Util.encrypt_CBC_Padding(myKeyBytes, myIvBytes, data.getBytes(charset));
        String encryptedHexString = ByteUtils.toHexString(encryptedBytes);
        System.out.println("CBC加密后的数据HexString：" + encryptedHexString);
        byte[] decryptedBytes = SM4Util.decrypt_CBC_Padding(myKeyBytes, myIvBytes, ByteUtils.fromHexString(encryptedHexString));
        System.out.println("CBC解密后的数据：" + new String(decryptedBytes, charset));
    }

    @Test
    public void testMac() throws Exception {
        byte[] key = SM4Util.generateKey();
        byte[] iv = SM4Util.generateKey();

        byte[] mac = SM4Util.doCMac(key, SRC_DATA_24B);
        System.out.println("CMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        mac = SM4Util.doGMac(key, iv, 16, SRC_DATA_24B);
        System.out.println("GMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        byte[] cipher = SM4Util.encrypt_CBC_NoPadding(key, iv, SRC_DATA_32B);
        byte[] cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        mac = SM4Util.doCBCMac(key, iv, null, SRC_DATA_32B);
        if (!Arrays.equals(cipherLast16, mac)) {
            Assert.fail();
        }
        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        cipher = SM4Util.encrypt_CBC_Padding(key, iv, SRC_DATA_32B);
        cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        mac = SM4Util.doCBCMac(key, iv, SRC_DATA_32B);
        if (!Arrays.equals(cipherLast16, mac)) {
            Assert.fail();
        }
        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
    }
}
