package youre package;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.apache.commons.codec.binary.Base64;
// 위의 라이브러리는 의존성 추가 https://mvnrepository.com/artifact/commons-codec/commons-codec/1.9

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import androidx.annotation.RequiresApi;

public class KEYSTORE {

/**사용처
1. sharedpreferences xml rooting보안
2. 앱내의 암호키(RSA:개인키암호화에 사용/ AES:대칭키암호화에 사용) 보안 **/

    private final static String alias = "NetworkSecurity"; // 키스토어 에서 사용할 별칭
    private static KeyGenerator keyGenerator;
    private static KeyGenParameterSpec keyGenParameterSpec;

    @RequiresApi(api = Build.VERSION_CODES.M) // 사용할 키는 AES 대칭키입니다. 마쉬멜로우부터 지원해줍니다.
    public static void keyStore_init(){ // KeyStore 초기화 메소드

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore"); // AndroidKeyStore를 정확히 입력해야 키 스토어에 접근합니다.
            keyStore.load(null);

            if(!keyStore.containsAlias(alias)){ // 지정된 별칭으로 키 미 생성 시 새롭게 키 생성
                // 다음은 생성할 키 알고리즘입니다.
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
                keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                        // 첫 번째, 인자는 별칭  두 번째, 인자는 key사용목적 암호화&복호화가 목적입니다.
                        alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC) // 세 번째, 인자는 운용할 블록모드
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7) //네 번째, 인자는 사용할 패딩 값
                        .setRandomizedEncryptionRequired(false)
                        .build(); // 초기화 완료

                keyGenerator.init(keyGenParameterSpec); // 키 생성을 위해 정의한 keyGenParameterSpec을 로드
                keyGenerator.generateKey(); // 대칭 키 생성
            }

        } catch (NoSuchAlgorithmException e) {
           System.err.println("Keystore init NoSuchAlgorithmException error");
        } catch (NoSuchProviderException e) {
            System.err.println("Keystore init NoSuchProviderException error");
        } catch (KeyStoreException e) {
            System.err.println("Keystore init KeyStoreException error");
        } catch (CertificateException e) {
            System.err.println("Keystore init CertificateException error");
        } catch (IOException e) {
            System.err.println("Keystore init IOException error");
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Keystore init InvalidAlgorithmParameterException error");
        }
    }
    
/* ****
String 값으로 넣어 String 값으로 반환되게 메소드를 구성했습니다. 
* *****/

    // 키스토어의 AES대칭키로 데이터 암호화하는 메소드
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static String keyStore_Encryption(String str){
        String keyStore_Encryption_DATA="";
        String iv = "";
        Key keySpec;
        String key = "";

        try {
            KeyStore keyStore = java.security.KeyStore.getInstance("AndroidKeyStore"); // Android KeyStore 접근
            keyStore.load(null); // 로드
            KeyStore.SecretKeyEntry secretKeyEntry =
                    (KeyStore.SecretKeyEntry) keyStore.getEntry(alias,null); // 별칭에 맞게 비밀키 접근
            SecretKey secretKey = secretKeyEntry.getSecretKey(); // 대칭키 반환

            // 키는 'String'형태로 반환
            if((Build.VERSION.SDK_INT <= Build.VERSION_CODES.N))
                key = new String(Base64.encodeBase64(secretKey.getEncoded()));
            else
                key = Base64.encodeBase64String(secretKey.getEncoded());

            iv = key.substring(0,16);
            byte[] keyBytes = new byte[16];
            byte[] b = key.getBytes("UTF-8");
            int len = b.length;
            if(len > keyBytes.length)
                len = keyBytes.length;
            System.arraycopy(b, 0, keyBytes, 0, len); // b의 0번지 부터 len길이 만큼 keybytes 0번지부터 복사
            keySpec = new SecretKeySpec(keyBytes, "AES");

            Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
            c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes())); // 암호화 준비

            // AES 암호화
            byte[] encrypted = c.doFinal(str.getBytes("UTF-8"));

            // 누가버전까지는 Base64.encodeBase64String NotMethod 이슈발생
            // 암호화된 데이터, 인코딩 후 'String'으로 반환
            if((Build.VERSION.SDK_INT <= Build.VERSION_CODES.N))
                keyStore_Encryption_DATA = new String(Base64.encodeBase64(encrypted));
            else
                keyStore_Encryption_DATA = Base64.encodeBase64String(encrypted); 

        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("keyStore_Encryption InvalidAlgorithmParameterException error");
        } catch (NoSuchPaddingException e) {
            System.err.println("keyStore_Encryption NoSuchPaddingException error");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("keyStore_Encryption NoSuchAlgorithmException error");
        } catch (InvalidKeyException e) {
            System.err.println("keyStore_Encryption InvalidKeyException error");
        } catch (BadPaddingException e) {
            System.err.println("keyStore_Encryption BadPaddingException error");
        } catch (IllegalBlockSizeException e) {
            System.err.println("keyStore_Encryption IllegalBlockSizeException error");
        } catch (UnsupportedEncodingException e) {
            System.err.println("keyStore_Encryption UnsupportedEncodingException error");
        } catch (CertificateException e) {
            System.err.println("keyStore_Encryption CertificateException error");
        } catch (KeyStoreException e) {
            System.err.println("keyStore_Encryption KeyStoreException error");
        } catch (UnrecoverableEntryException e) {
            System.err.println("keyStore_Encryption UnrecoverableEntryException error");
        } catch (IOException e) {
            System.err.println("keyStore_Encryption IOException error");
        }
        return keyStore_Encryption_DATA;
    }
    
    
/* ****
String 값으로 넣어 String 값으로 반환되게 메소드를 구성했습니다. 
* *****/

     // 키스토어의 AES대칭키로 데이터 복호화하는 메소드
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static String keyStore_Decryption(String str){
        String keyStore_Decryption_DATA="";
        String iv = "";
        Key keySpec;
        String key = "";

        try {
            KeyStore keyStore = java.security.KeyStore.getInstance("AndroidKeyStore"); // Android KeyStore 접근
            keyStore.load(null); // 로드
            KeyStore.SecretKeyEntry secretKeyEntry =
                    (KeyStore.SecretKeyEntry) keyStore.getEntry(alias,null); // 별칭에 맞게 비밀키 접근
            SecretKey secretKey = secretKeyEntry.getSecretKey(); // 비밀키 반환

            
            // 비밀키는 'String'형태로 반환
            if((Build.VERSION.SDK_INT <= Build.VERSION_CODES.N))
                key = new String(Base64.encodeBase64(secretKey.getEncoded()));
            else
                key = Base64.encodeBase64String(secretKey.getEncoded());

            iv = key.substring(0,16);
            byte[] keyBytes = new byte[16];
            byte[] b = key.getBytes("UTF-8");
            int len = b.length;
            if(len > keyBytes.length)
                len = keyBytes.length;
            System.arraycopy(b, 0, keyBytes, 0, len); // b의 0번지 부터 len길이 만큼 keybytes 0번지부터 복사
            keySpec = new SecretKeySpec(keyBytes, "AES");


            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes("UTF-8"))); //

            // 암호화된 인코딩 데이터 -> 디코딩
            byte[] byteStr = Base64.decodeBase64(str.getBytes());
            // 디코딩된 암호문 -> 복호화 후 'String'으로 반환
            keyStore_Decryption_DATA = new String(cipher.doFinal(byteStr),"UTF-8");

        } catch (KeyStoreException e) {
            System.err.println("keyStore_Encryption KeyStoreException error");
        } catch (CertificateException e) {
            System.err.println("keyStore_Encryption CertificateException error");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("keyStore_Encryption NoSuchAlgorithmException error");
        } catch (IOException e) {
            System.err.println("keyStore_Encryption IOException error");
        } catch (UnrecoverableEntryException e) {
            System.err.println("keyStore_Encryption UnrecoverableEntryException error");
        } catch (InvalidKeyException e) {
            System.err.println("keyStore_Encryption InvalidKeyException error");
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("keyStore_Encryption InvalidAlgorithmParameterException error");
        } catch (NoSuchPaddingException e) {
            System.err.println("keyStore_Encryption NoSuchPaddingException error");
        } catch (BadPaddingException e) {
            System.err.println("keyStore_Encryption BadPaddingException error");
        } catch (IllegalBlockSizeException e) {
            System.err.println("keyStore_Encryption IllegalBlockSizeException error");
        }
        return keyStore_Decryption_DATA;
    }
}
