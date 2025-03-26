# Generating a random, secure key for JWT creation

[Creating a JWT](../spring/SecurityWithJsonWebtokens.md) requires a random, secure key of at least 32 bytes [(256 bits for SHA256 encryption)](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2).
This key is used when generating the Hash-based Message Authentication Code (HMAC) which is used to sign the JWT.

Here's a quick snippet for generating this key:

```java
import java.security.SecureRandom;
import java.util.Base64;

public class KeyGenerator {
    private int byteCount;

    public KeyGenerator(int byteCount) {
        this.byteCount = byteCount;
    }

    public String generateRandomKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[byteCount];
        secureRandom.nextBytes(key);
        String encodedKey = Base64.getEncoder().encodeToString(key);
        return encodedKey;
    }
}
```

Note that it's not strictly required to store the key using Base64, but it is highly recommended for cross-compatibility with
other mainstream platforms (AWS Secrets Manager, Kubernetes Secrets, HashiCorp Vault often store secrets in Base64 format).

Be sure to use Base64 when decoding the string within the application so the underlying binary is interpretted correctly.

#### Simple JwtService example to authenticate a user in Spring Boot

```java
@Service
public class JwtService {
    @Value("${jwt.secret}") // injected from application properties file
    private String SECRET_KEY;

    private SecretKey key;

    @Autowired
    private AppUserRepository userRepository;

    @PostConstruct // needed because SECRET_KEY is injected after field initialization
    public void init() {
        var bytes = Base64.getDecoder().decode(SECRET_KEY); // using Base64 for proper byte interpretation
        key = Keys.hmacShaKeyFor(bytes);
    }

    public String generateToken(String username) {
        var user = userRepository.findByUsername(username);
        var roles = AppUserMapper.INSTANCE.roleSetToStringList(user.getRoles());
        final int oneHour = 1000 * 60 * 60;
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + oneHour))
                .signWith(key)
                .compact();
    }
}
```
