package youre package;

import org.apache.commons.codec.binary.Base64;
// 위의 라이브러리는 의존성 추가 https://mvnrepository.com/artifact/commons-codec/commons-codec/1.9

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**키 생성 및 암호화는 가급적 개발보안가이드의 권고사항을 지켜주시면 안전하게 데이터를 암호화/복호화 하실수 있습니다.**/

public class RSA {

    public static String publicKEY="";
    public static String privateKEY="";

    // RSA 비대칭키 생성 
    public static void rsaKeyGen() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom(); // 안전한 난수 생성 'math random'보다 보안 강도가 높음
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); // 키생성에 사용할 암호 알고리즘
        keyPairGenerator.initialize(2048, secureRandom); // 충분한 키 길이 및 난수를 이용하여 키 초기화
        KeyPair keyPair = keyPairGenerator.genKeyPair(); // 키 쌍 생성

        PublicKey publicKey = keyPair.getPublic(); // 생성된 공개키 추출
        PrivateKey privateKey = keyPair.getPrivate(); // 생성된 개인키 추출

         // 누가버전까지는 Base64.encodeBase64String NotMethod 이슈발생
        if((Build.VERSION.SDK_INT > Build.VERSION_CODES.N)){
            publicKEY = new String(Base64.encodeBase64(publicKey.getEncoded()));
            privateKEY = new String(Base64.encodeBase64(privateKey.getEncoded()));
        }else{
            publicKEY = Base64.encodeBase64String(publicKey.getEncoded()); // 공개키 객체를 'String'으로 변환
            privateKEY = Base64.encodeBase64String(privateKey.getEncoded()); // 개인키 객체를 'String'으로 변환
        }
        
        
        /**이렇게 String 형태로 가지고있으면 네트웤 전송 시, 객체변환/인코딩의 번거로움이 없어질 것같습니다.**/
    }

    /*암호화*/
    public static String rsaEncryption(String plainData, String stringPublicKey) throws BadPaddingException,
            IllegalBlockSizeException, InvalidKeySpecException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

            // 평문으로 전달받은 'String공개키'를 '공개키 객체'로 만드는 과정
            byte[] bytePublicKey = Base64.decodeBase64(stringPublicKey.getBytes());
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            // 만들어진 공개키객체를 기반으로 암호화를 설정하는 과정
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey); // 암호화 준비

            // 암호화 진행
            byte[] byteEncryptedData = cipher.doFinal(plainData.getBytes());
                
            // 암호화 데이터, 인코딩 후 'String'으로 반환
            if((Build.VERSION.SDK_INT > Build.VERSION_CODES.N))
               return new String(Base64.encodeBase64(byteEncryptedData));
            else
               return Base64.encodeBase64String(byteEncryptedData);
    }

    /*복호화*/
    public static String rsaDecryption(String encryptedData, String stringPrivateKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

            // 평문으로 전달받은 'String개인키'를 '개인키 객체'로 만드는 과정
            byte[] bytePrivateKey =  Base64.decodeBase64(stringPrivateKey.getBytes());
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            // 만들어진 개인키객체를 기반으로 복호화를 설정하는 과정
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey); // 복호화 준비

            // 암호화된 인코딩 데이터를 디코딩 진행
            byte[] byteEncryptedData = Base64.decodeBase64(encryptedData.getBytes());

            // 복호화 진행
            byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);

            // 복호화 후 'String'으로 반환
            return new String(byteDecryptedData);
        }
}
