package yourpackage;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SQLFilter {

    private static final Pattern SpecialCharsList = Pattern.compile("['\"\\-#()@;=*/+]"); // 특수문자 검증
    private static final String defendList = "(union|select|from|where|insert|update|delete)"; // sql문 검증
    private static final Pattern sql_pattern = Pattern.compile(defendList,Pattern.CASE_INSENSITIVE); // 대소문자 구분하지 않음

    public static boolean sqlFilter(String value){
        boolean result=false; //default 셋팅
        try {
            value = URLDecoder.decode(value,"euc-kr"); // 인코딩 우회 방지 적용
            value = SpecialCharsList.matcher(value).replaceAll(""); // 1단계 특수문자 검증
            Matcher matcher = sql_pattern.matcher(value); // 2단계 DML 조작어 검증 & union

            if(matcher.find()){
                result = true; // SQL 발견
            }else
                result = false; //SQL로부터 안전

        } catch (UnsupportedEncodingException e) {
            System.err.println("SQLFilter error");
        }
        return result;
    }
}
