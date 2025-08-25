#📝 개인 개발 기록

## 👤 역할

- **회원/예약 관련 기능 및 보안(Spring Security)** 담당
- 주요 담당 기능:
    - 로그인/회원가입
    - 마이페이지
        - 예약 조회 및 예약 취소
        - 북마크 기능
    - 권한(Role) 관리
    - AOP를 활용한 공통 로깅 처리

---

## ⚙️ 개발한 기능 & 코드 샘플

### 1️⃣ 로그인 / 권한(Role) 부여

- **역할**: Role 기반 권한 관리 적용 (`ROLE_ADMIN`)
- **개선 과정**:
    - **처음 시도**: 회원/관리자 테이블을 분리하여 구현
        - 문제: 서버가 하나라 로그인 후 세션/Principal 객체를 공유 → 관리자 로그인 시 일반 사용자 정보가 불러와지지 않음
        - 결과: 마이페이지 등에서 Null 오류 발생
    - **해결 방법**: 회원과 관리자를 **하나의 테이블에 통합**하고, 별도의 `ROLE` 테이블을 두어 권한을 부여
        - 예) 관리자에게 `ROLE_ADMIN`
        - 추후 필요 시 `ROLE_MANAGER`(숙소 관리자) vs `ROLE_ADMIN`(통합 관리자)로 확장 가능

<details>
<summary>CustomUserDetailsService 예시</summary>

```java
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		log.warn("Load User By UserID : " + username);

		MemberVO vo = commonMapper.read(username);

		if (vo == null) {
			log.warn("User not found : " + username);
	        throw new UsernameNotFoundException("User not found: " + username);
	    }

		return new CustomUser(vo);
}
```
</details>

---

### 2️⃣ 회원가입 (Password 암호화)

- 회원 가입 시 비밀번호를 암호화하여 DB에 저장
- Spring Security `BCryptPasswordEncoder` 사용
<details open>
<summary>CommonServiceImpl.java 예시</summary>

```java
@Autowired
private BCryptPasswordEncoder passwordEncoder;

// 회원가입 처리 예시
String encodedPassword = passwordEncoder.encode(vo.getMiPw());
vo.setMiPw(encodedPassword);	// 비밀번호 인코딩
int result = commonMapper.handleRegister(vo);
```
</details>

---

### 3️⃣ 로그인 (Spring Security 설정)

- 로그인 처리 및 세션/Principal 관리
<details open>
<summary>security-context.xml 예시</summary>

```xml
<security:http use-expressions="true" entry-point-ref="securityAuditHandler">
  <security:intercept-url pattern="/admin/**" access="hasRole('ROLE_ADMIN')" />
  
  <!-- 403 핸들러 -->
  <security:access-denied-handler ref="securityAuditHandler"/>
  
  <security:form-login login-page="/login" 
		  authentication-success-handler-ref="securityAuditHandler" 
		  authentication-failure-handler-ref="securityAuditHandler" />
	<security:logout logout-url="/logout" logout-success-url="/" 
			invalidate-session="true" />
</security:http>

<security:authentication-manager>
	<security:authentication-provider user-service-ref="customUserDetailsService">
		<security:password-encoder ref="bcryptPasswordEncoder" />
	</security:authentication-provider>
</security:authentication-manager>
```
</details>

---

### 4️⃣ 권한(Role) 관리

- 테이블 구조 및 역할 부여 방식
- DB에서 Role 조회 후 `CustomUser`에서 적용
<details>
<summary>CommonMapper.xml 예시</summary>

```xml
<select id="read" resultMap="memberMap">
	SELECT 
		mi.mi_id,
		mi.mi_pw,
		mi.mi_name,
		mi.mi_gender,
		mi.mi_birth,
		mi.mi_phone, 
		mi.mi_isad,
		mi.mi_date,
		mi.mi_enabled,
		mr.mr_name 
	FROM t_member_info mi 
	LEFT JOIN t_member_role mr ON mi.mi_id = mr.mi_id 
	WHERE mi.mi_id = #{miId}
</select>
```
</details>

- `CustomUser`에서 Role을 `SimpleGrantedAuthority`로 변환하여 Security에 전달
<details open>
<summary>CustomUser.java 예시</summary>

```java
public CustomUser(MemberVO vo) {
	super(vo.getMiId(), vo.getMiPw(), vo.getRoles().stream()
					.map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
	this.member = vo;
}
```
</details>

---

### 5️⃣ 예약 (Flatpickr 적용)

- **처음 시도**: 체크인 불가 날짜를 전부 `disable` 처리 → 체크아웃 날짜용 클래스를 붙이려 했으나 `disable`이 다른 클래스 제거
- **해결 방법**:
    - 체크아웃일 경우에는 `disable` 대신 **커스텀 class** 부여
    - 즉, **체크인/체크아웃 조건에 따라 다른 스타일/제약**을 적용하는 방식으로 변경
<details open>
<summary>stayDetailBooking.js 예시</summary>

```jsx
// 체크인, 체크아웃 불가 날짜 불러오기
fetch(`/stay/room/unavailable-dates/${siId}/${riId}`)
  .then((res) => res.json())
  .then((data) => {
    const rawUnavailable = data.unavailableCheckin || [];
    checkoutOnly = data.checkoutOnly || [];
     // disable에는 '체크인 불가'만 넣는다 (checkoutOnly는 제외)
    unavailableCheckin = rawUnavailable.filter(d => !checkoutOnly.includes(d));

    // 달력에 비활성 날짜 설정
    datePicker.set("disable", unavailableCheckin);
    datePicker.redraw();

    if (startDate) {
      const startStr = formatDateForServer(startDate);
      if (rawUnavailable.includes(startStr)) {
        clearDateSelection();
      }
    } else {
      updateDateDisplay();
    }
  })
  .catch((err) => console.error("예약 불가 날짜 불러오기 실패:", err));
```
</details>


---

### 6️⃣ 마이페이지

- 예약 내역 확인
- 예약 취소 기능
- 북마크 내역 조회

---

### 7️⃣ 북마크

- 북마크 테이블에 저장 + 숙소 테이블(`accommodation`)의 **bookmark_count 컬럼 증가/감소**
- **Transaction 적용**
    - 북마크 추가/삭제와 숙소 테이블의 카운트 갱신을 하나의 트랜잭션으로 처리
    - 실제 구현은 `@Transactional` 어노테이션으로 간단하게 적용

<details open>
<summary>CustomUserDetailsService 예시</summary>

```java

@Transactional(rollbackFor = Exception.class)
    public int addBookmark(String miId, int siId) {
    int inserted = bookmarkMapper.addBookmark(miId, siId);
    if (inserted == 1) { // 새로 추가된 경우에만 카운트 +1
        stayMapper.incBookmarkCount(siId);
    }
    return inserted;
}

@Transactional(rollbackFor = Exception.class)
    public int deleteBookmark(String miId, int siId) {
    int deleted = bookmarkMapper.deleteBookmark(miId, siId);
    if (deleted == 1) { // 실제 삭제된 경우에만 -1
        stayMapper.decBookmarkCount(siId);
    }
    return deleted;
}
```
</details>
 

---

### 8️⃣ AOP 기반 HTTP 요청/응답 로깅

프로젝트에서는 Spring AOP를 활용하여 **컨트롤러 계층에서 발생하는 모든 HTTP 요청과 응답**을 로깅했습니다.

이를 통해 누가 어떤 요청을 했는지, 응답 상태와 소요 시간, 예외 발생 여부를 쉽게 파악할 수 있습니다.

---

### 적용 방식

- `@Aspect`와 `@Around` 어노테이션을 활용하여 컨트롤러 메서드 실행 전후에 로깅
- 포인트컷: `com.hotel.controller` 패키지 및 하위 패키지의 모든 메서드
- Spring Security와 연동하여 로그인 사용자 정보 포함
- `ResponseEntity` 또는 `HttpServletResponse`에서 상태 코드 확인
- 메서드 실행 시간 측정

---

### 로그 항목

| 항목 | 설명 |
| --- | --- |
| user | 요청한 사용자 (`anonymous`는 비로그인 상태) |
| HTTP 메서드 | GET, POST 등 |
| URI 및 쿼리 | 요청 주소와 쿼리스트링 |
| 상태 코드 | 200, 404, 500 등 |
| 컨트롤러.메서드 | 실제 실행된 컨트롤러와 메서드 |
| 소요 시간 | 메서드 실행 시간(ms) |
| 예외 정보 | 예외 발생 시 클래스명과 스택트레이스 |

---

### 예시 코드
<details>
<summary>LogAdvice.java 예시</summary>

```java
@Aspect
@Component
@Log4j
public class LogAdvice {

    @Pointcut("execution(* com.hotel.controller..*(..))")
    public void controllerLayer(){}

    @Around("controllerLayer()")
    public Object logHttp(ProceedingJoinPoint pjp) throws Throwable {
        long start = System.currentTimeMillis();

        ServletRequestAttributes at = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest req = (at != null) ? at.getRequest() : null;

        String http = (req != null) ? req.getMethod() : "-";
        String uri  = (req != null) ? req.getRequestURI() : "-";
        String qs   = (req != null && req.getQueryString()!=null) ? "?"+req.getQueryString() : "";
        String user = "anonymous";
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) user = auth.getName();

        Signature sig = pjp.getSignature();
        String cls = sig.getDeclaringType().getSimpleName();
        String mtd = sig.getName();

        try {
            Object ret = pjp.proceed();
            long took = System.currentTimeMillis() - start;

            int status = 200;
            if (ret instanceof ResponseEntity) {
                status = ((ResponseEntity<?>) ret).getStatusCodeValue();
            } else if (at != null && at.getResponse() != null) {
                status = at.getResponse().getStatus();
            }

            log.info(String.format("[HTTP] user=%s %s %s%s -> %d %s.%s() (%d ms)",
                    user, http, uri, qs, status, cls, mtd, took));
            return ret;
        } catch (Throwable ex) {
            long took = System.currentTimeMillis() - start;
            log.error(String.format("[HTTP] user=%s %s %s%s -> ERROR %s.%s() (%d ms) %s",
                    user, http, uri, qs, cls, mtd, took, ex.getClass().getSimpleName()), ex);
            throw ex;
        }
    }
}
```
</details>

### 로그 예시

- **정상 요청**
    
    `[HTTP] user=jiseon GET /hotel/list?page=1 -> 200 HotelController.list() (123 ms)`
    
- **예외 발생**
    
    `[HTTP] user=anonymous POST /hotel/reserve -> ERROR ReservationController.reserve() (45 ms) NullPointerException`

---

## 💡 어려웠던 점 & 해결 방법

| 문제 상황 | 해결 방법 |
| --- | --- |
| 회원/관리자 로그인 분리 문제 | 회원과 관리자를 하나의 테이블로 합치고, `ROLE` 테이블에서 권한 관리 (관리자에게`ROLE_ADMIN` 권한 부여) |
| 예약 불가 날짜 처리 | `disable` 대신 **체크아웃 전용 class 부여**로 조건 분리 |
| 북마크 저장 시 두 테이블 동기화 | `@Transactional` 적용으로 **북마크 테이블 + 숙소 테이블 동시 갱신** |
| 중복 로깅 코드 문제 | AOP 적용 → 공통 로깅처리 분리 |

---

## 📈 배운 점

- **Role 기반 권한 관리**를 통해 확장성 높은 보안 구조 설계
- 단순 기능 구현이 아닌 **UI/UX 흐름 고려**한 예약 날짜 처리 경험
- 트랜잭션을 직접 적용해 **데이터 정합성** 보장 경험
- AOP로 **관심사 분리**의 필요성과 장점을 체감

---

## 🚀 앞으로 개선하고 싶은 부분

- 카카오 소셜 로그인 연동
- AWS 배포 후 실 서비스 환경에서 성능 검증
