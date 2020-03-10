package tt;

import org.mindrot.jbcrypt.BCrypt;

public class BcryptTest {
	public static void main(String[] args) {
		String password = "testing";
		String compare_first_password = "testing";
		String compare_second_password = "testing11";
		
		System.out.println("not hash: "+password);	
		// 레인보우 테이블 방어를 위해 salt와 같이 hash진행
		password = BCrypt.hashpw(password, BCrypt.gensalt(10));
		System.out.println("hash: "+password);
		
		// 올바른 비밀번호 입력일 시 , true 반환
		// 올바르지 않은 비밀번호 입력할 시, fasle 반환
 		System.out.println("find hash compare: "+BCrypt.checkpw(compare_first_password, password));
		System.out.println("not find hash compare: "+BCrypt.checkpw(compare_second_password, password));
	}
}
