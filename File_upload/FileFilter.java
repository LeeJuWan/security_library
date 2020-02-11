package your package;

import org.apache.tika.Tika;
// 위의 라이브러리는 maven repo https://mvnrepository.com/artifact/org.apache/tika/0.2 에서 다운받으세요.

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;


// 파일업로드 취약점은 악성코드 파일 삽입을 통해 시스템 접근 가능 및 정보 유출과 직결될 수 있습니다.
// 다음의 코드는 1. 인코딩 우회 감지 2. MIME 감지 3. 전체 이름을 통한 확장자 체크 4. 서버에 부하를 줄 수 있는 파일의 크기
// 5. 실행 가능한 파일 여부를 확인하는 절차를 가져갑니다.

public class FileFilter {

    public static boolean fileFilter(File fileData){ // 파라미터를 통해 파일 데이터를 입력 시, 참 / 거짓으로 악성유무 판단
    
        final int fileAllowSize= 10240000; //10MB이하
        boolean result= false; //default 셋팅

        Tika tika = new Tika(); // MIME 타입 확인을 위해 tika 생성

        if(fileData != null && "".equals(fileData.getName())){ // null 체크 및 공백 체크
            String file= "";
            try{
                file= URLDecoder.decode(fileData.getName(),"euc-kr"); // 1단계 인코딩 우회 방지

                if(fileData.length()>fileAllowSize || fileData.canExecute()) // 2단계 파일의 사이즈 & 파일 실행여부 확인
                    result = true; // 위험한 형식의 파일 발견
                else{
                    if(file.toLowerCase().endsWith(".jpg") || file.toLowerCase().endsWith(".png") ||
                    file.toLowerCase().endsWith(".jpeg"))
                    { // 3단계 문자열의 마지막 확장자 확인
                        // test.jpg.asp의 '.asp'를 막기위해 파일 전체이름 리딩
                        // 리딩된 파일 이름을 통해 끝부분의 확장자 .jpg 또는 .png가 맞다면 2단계 검증 완료

                        String mimeType = tika.detect(fileData); // 4단계 MIME type 확인
                        if(mimeType.startsWith("image")){
                            // test.txt->test.jpg로 변환 가능
                            // 변환된 test.jpg 파일의 mime type은 -> text/plane
                            result = false; // 파일 확장자 안전함
                        }
                        else
                            result = true; // 위험한 형식의 파일 발견
                    }else
                        result = true; // 위험한 형식의 파일 발견

                }
            }catch (UnsupportedEncodingException e) {
                System.err.println("FileFilter error");
            } catch (IOException e) {
                System.err.println("FileFilter IOExcepiont error");
            }
        }
        else {
           result =true; //파일 null & 공백 파일
        }
        return  result;
    }
}
