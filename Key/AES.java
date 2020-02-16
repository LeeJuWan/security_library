package your package;

import org.apache.commons.codec.binary.Base64;
// 위의 라이브러리는 의존성 추가 https://mvnrepository.com/artifact/commons-codec/commons-codec/1.9

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**키 생성 및 암호화는 가급적 개발보안가이드의 권고사항을 지켜주시면 안전하게 데이터를 암호화/복호화 하실수 있습니다.**/

public class AES {

    public static String secretKEY="";

      // AES 대칭키 생성 
    public static void aesKeyGen(){
    
        KeyGenerator generator = KeyGenerator.getInstance("AES");  // 키생성에 사용할 암호 알고리즘
        SecureRandom secureRandom = new SecureRandom(); // 안전한 난수 생성 'math random'보다 보안 강도가 높음
        generator.init(256, secureRandom); // 충분한 키 길이 및 난수를 이용하여 키 초기화
        Key secureKey = generator.generateKey();
        
        // 누가버전까지는 Base64.encodeBase64String NotMethod 이슈발생
        if((Build.VERSION.SDK_INT > Build.VERSION_CODES.N))
            secretKEY = Base64.encodeBase64String(secureKey.getEncoded()); // 대칭키 객체를 'String'으로 변환
        else
            secretKEY = new String(Base64.encodeBase64(secureKey.getEncoded()));
       
        /**이렇게 String 형태로 가지고있으면 네트웤 전송 시, 객체변환/인코딩의 번거로움이 없어질 것같습니다.**/
    }

// AES 암호는 대칭암호로써, 운용모드와 패딩이라는 절차가 들어가 있습니다.
// 그렇기에 클라이언트-서버간의 운용모드/패딩은 동일하게 셋팅해주세요.


    /*암호화*/
    public static String aesEncryption(String str, String key) throws UnsupportedEncodingException,
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        String iv = "";
        Key keySpec;
        
        // 벡터 값을 KEY를 통해 추출
        iv = key.substring(0,16);
        byte[] keyBytes = new byte[16];
        byte[] b = key.getBytes("UTF-8");
        int len = b.length;
        if(len > keyBytes.length)
            len = keyBytes.length;
        System.arraycopy(b, 0, keyBytes, 0, len); // b의 0번지 부터 len길이 만큼 keybytes 0번지부터 복사
        keySpec = new SecretKeySpec(keyBytes, "AES");
        
        // 운용모드의 권고사항은 'CBC'로 하시면됩니다.
        // 현재 패딩 방법이 'PKCS5Padding'도 존재하는데 'PKCS7Padding'이 더 상위버전이라고 해서 사용했습니다.
        // KeyStore에서도 패딩을 'PKCS7Padding' 지원하고 있으니 참고해주세요
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding"); 
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes())); // 암호화 준비

        // AES 암호화
        byte[] encrypted = cipher.doFinal(str.getBytes("UTF-8"));

        // 암호화된 데이터, 인코딩 후 'String'으로 반환
        if((Build.VERSION.SDK_INT > Build.VERSION_CODES.N)){
            return new String(Base64.encodeBase64(encrypted));
        else
            return Base64.encodeBase64String(encrypted);
    }

    public static String aesDecryption(String str, String key) throws UnsupportedEncodingException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        String iv = "";
        Key keySpec;

        // 벡터 값을 KEY를 통해 추출
        iv = key.substring(0,16);
        byte[] keyBytes = new byte[16];
        byte[] b = key.getBytes("UTF-8");
        int len = b.length;
        if(len > keyBytes.length)
            len = keyBytes.length;
        System.arraycopy(b, 0, keyBytes, 0, len); // b의 0번지 부터 len길이 만큼 keybytes 0번지부터 복사
        keySpec = new SecretKeySpec(keyBytes, "AES");

        // 암호화와 동일하게 운용모드 , 패딩 방법 구성 진행
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes("UTF-8"))); // 복호화 준비

        // 암호화된 인코딩 데이터, 디코딩 변환
        byte[] byteStr = Base64.decodeBase64(str.getBytes());
        // 디코딩된 암호화 데이터, 복호화 후 'String'으로 반환
        return new String(cipher.doFinal(byteStr),"UTF-8");
    }
}
