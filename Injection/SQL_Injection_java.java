/**
* SQL인젝션 입력 값 검증
**/
public static String SQLFilter(String value) {
  try {
        value = URLDecoder.decode(value, "euc-kr"); // URL 인코딩 우회 방지
        value = value.toLowerCase(); // 소문자로 변경
        value = value.replaceAll("select", " ")
        .replaceAll("from", " ")
        .replaceAll("where", " ")
        .replaceAll("union", " ")
        .replaceAll("delete", " ")
        .replaceAll("insert", " ")
        .replaceAll("update", " ")
        .replaceAll("#", " ")
        .replaceAll("-", " ")
        .replaceAll("+", " ")
        .replaceAll("@", " ")
        .replaceAll("/", " ")
        .replaceAll("\\", " ")
        .replaceAll("'", " ");
      } catch (UnsupportedEncodingException e) {
        // TODO Auto-generated catch block
        System.err.println("SQLFilter UnsupportedEncodingException error");
      }
      return value;
}
