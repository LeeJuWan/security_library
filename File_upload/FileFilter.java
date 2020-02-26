package your package;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;


// 파일업로드 취약점은 악성코드 파일 삽입을 통해 시스템 접근 가능 및 정보 유출과 직결될 수 있습니다.
// 다음의 코드는 1. 인코딩 우회 감지 2. MIME 감지 3. 전체 이름을 통한 확장자 체크 4. 서버에 부하를 줄 수 있는 파일의 크기
// 5. 실행 가능한 파일 여부를 확인하는 절차를 가져갑니다.

public class FileFilter {

    public static boolean fileFilter(File fileData){
        final int fileAllowSize= 10240000; //10MB이하
        boolean result= true; //default 셋팅

        if(!"".equals(fileData.getName())){
            String file= "";
            try{
                file= URLDecoder.decode(fileData.getName(),"euc-kr"); // 1단계 인코딩 우회 검증

                if(fileData.length()>fileAllowSize) { // 2단계 파일의 사이즈
                    result = true;
                }else{
                    if(fileData.canExecute()){ // 3단계 파일 실행여부 검증
                        result = true;
                    }else{

                        String [] array=file.split("\\."); // ex) test.jsp%00.jpg 검출목적
                        if(array[1].toLowerCase().endsWith("jpg") || array[1].toLowerCase().endsWith("png") ||
                                array[1].toLowerCase().endsWith("jpeg")) // 4단계 문자열의 마지막 확장자 검증
                        {
                            // 5단계 mime type 검증, mime type 변환 진행
                            MimeTypeMap mimeTypeMap = MimeTypeMap.getSingleton();
                            String extenstion = MimeTypeMap.getFileExtensionFromUrl(fileData.getName());
                            String mime_Type = mimeTypeMap.getMimeTypeFromExtension(extenstion);

                            if(mime_Type.toLowerCase().startsWith("image")){
                                result = false; // 안전한 파일
                            } else // mime 타입 없을 시 null 반환
                                result = true; // 위험한 형식의 파일 발견

                        }else
                            result = true; // 위험한 형식의 파일 발견
                    }
                }
            }catch (UnsupportedEncodingException e) {
                System.err.println("FileFilter UnsupportedEncodingException error");
            }
        }
        else {
            result =true; //공백 파일
        }
        return  result;
    }
}
