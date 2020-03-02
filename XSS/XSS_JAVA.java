/**
	 * XSS 입력 값 검증
	 * */
	public static String XSSFilter(String value) {
		
		try {
			value = URLDecoder.decode(value, "euc-kr");
			value = value.toLowerCase();
			value = value.replaceAll("<", "&lt;")
					.replaceAll(">", "&gt;")
					.replaceAll("/", "&#x2F;")
					.replaceAll("&", "&#38;")
					.replaceAll("#", "&#35;")
					.replaceAll("'", "&apos;")
					.replaceAll("\\", "&quto;")
					.replaceAll("script", " ")
					.replaceAll("img", " ")
					.replaceAll("iframe", " ")
					.replaceAll("onclick", " ");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			System.err.println("XSSFilter UnsupportedEncodingException error");
		}
		
		return value;
	}
