The following dependencies are necessary to enable Spring Security with JsonWebtoken for authentication/authorization.

```java
implementation 'org.springframework.boot:spring-boot-starter-security'
implementation 'io.jsonwebtoken:jjwt-api'
runtimeOnly 'io.jsonwebtoken:jjwt-impl'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson'
```

First create the user entity. This should store user info, including credentials (password).

```java
import java.util.HashSet;
import java.util.Set;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import io.onicodes.issue_tracker.models.issueAssignee.IssueAssignee;


@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
@Getter
@Setter
@ToString
@Entity
@Table(name = "users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @ManyToMany
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
}
```

Create the AppUserRepository for easy database persistence.

```java
import org.springframework.data.jpa.repository.JpaRepository;
import io.onicodes.issue_tracker.models.appUser.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    public AppUser findByUsername(String username);
}
```

`findByUsername(String username)` leverages Spring Data JPAs `findBy` derived query methods
to easily lookup a user by their username without explicitly writing a query for it.

Then create the AppUserDetails class, which implements the builtin UserDetails interface:

```java
import java.util.Collection;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import io.onicodes.issue_tracker.models.appUser.AppUser;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class AppUserDetails implements UserDetails {
    private final AppUser user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }
}
```

This class is composed of the AppUser entity and is effectively used to get user information
that is relevant for authentication/authorization.

Then create the JwtService class. This is used to generate Json Web Tokens (JWTs) as well as
parse JWTs to validate user credentials.

```java
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.onicodes.issue_tracker.entityToDtoMappers.AppUserMapper;
import io.onicodes.issue_tracker.repositories.AppUserRepository;
import jakarta.annotation.PostConstruct;

@Service
public class JwtService {
    @Value("${jwt.secret}") // injected from application properties file
    private String SECRET_KEY;
    private SecretKey key;

    @Autowired
    private AppUserRepository userRepository;

    @PostConstruct // needed because SECRET_KEY is injected after field initialization
    public void init() {
        key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
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

    public String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public List<String> extractRoles(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("roles", List.class);
    }

    public boolean validateToken(String token, String username) {
        return username.equals(extractUsername(token)) && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date());
    }
}
```

Next is implementing the authentication filter.

```java
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        try {
            String username = jwtService.extractUsername(token);
            List<String> roles = jwtService.extractRoles(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                var grantedRoles = roles
                    .stream()
                    .map(role -> new SimpleGrantedAuthority(role))
                    .collect(Collectors.toSet());

                UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                        new User(username, "", grantedRoles),
                        null,
                        grantedRoles
                    );
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (ExpiredJwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
```

Extending the `OncePerRequestFilter` built-in Spring class ensures `doFilterInternal` is
called only once per request. `doFilterInternal` performs the following:

#### retrieving the token

```java
        // retrieves the Authorization http header
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // if authHeader is null or does not start with 'Bearer ' then immediately skip JWT processing
            filterChain.doFilter(request, response);
            return;
        }
        // else, extract the token from the authHeader
        final String token = authHeader.substring(7);
```

#### creating and adding a new authentication token to the security context if the user's not yet authenticated

```java
        try {
            // parse token to extract username
            String username = jwtService.extractUsername(token);
            // parse token to extract roles
            List<String> roles = jwtService.extractRoles(token);
            // verify the username exists and the user is not already authenticated in the security context
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                var grantedRoles = roles
                    .stream()
                    .map(role -> new SimpleGrantedAuthority(role))
                    .collect(Collectors.toSet());
                // create a new authentication token
                UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                        // the principal is created from the builtin User class using the username,
                        // a blank string for the password (not needed after token's already been granted),
                        // and the Set of granted roles
                        new User(username, "", grantedRoles),
                        null, // null for password since again it's not needed here once the user's been authenticated
                        grantedRoles // same list used in Principal object
                    );
                // set the new authentication token in the security context for downstream request filters
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
```

#### handling expired jwt exception

```java
         catch (ExpiredJwtException e) {
            // returns 401 unauthorized error response with "Token expired" message
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            return;
        }
```

#### forward request to next filter in chain

```java
        // Regardless of whether the token was processed or an error occurred (outside of an early return),
        // the request is forwarded to the next filter in the chain.
        filterChain.doFilter(request, response);
```

The next step is configuring Spring Security.

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import io.onicodes.issue_tracker.security.jwt.JwtAuthenticationFilter;
import io.onicodes.issue_tracker.security.jwt.JwtService;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    public final JwtService jwtService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login", "/auth/register").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
```

1. The `securityFilterChain` bean is a chain of authentication filters; this is what's ultimately
   returned when `httpSecurity.build()` is called. The custom `JwtAuthenticationFilter` that was created earlier
   is added to the chain before the builtin `UsernamePasswordAuthenticationFilter` filter using `addFilterBefore`.
   This ensures that jwt based authentication is attempted first. The jwt authentication filter intercepts http requests
   and adds the jwt token to the security context if the token is valid, as shown earlier.

2. `.requestMatchers("/auth/login", "/auth/register").permitAll()` allows anyone to access the login page. This is important because
   unauthenticated users need a reachable endpoint to authenticate themselves.

3. `.anyRequest().authenticated()` requires authentication for any other requests that don't match the
   "/auth/login" or "/auth/register" endpoints.

4. `passwordEncoder` bean defines the encoder to use to securely store user passwords; here BCrypt is being used.

5. `authenticationManager` bean defines the authentication manager to use at the auth controller.

Now implement the AuthController that will be responsible for handling user authentication during login.

```java
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.onicodes.issue_tracker.dtos.AuthRequestDto;
import io.onicodes.issue_tracker.dtos.AuthResponseDto;
import io.onicodes.issue_tracker.security.jwt.JwtService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager; // bean defined earlier in SecurityConfig.java
    private final JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody AuthRequestDto credentials) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                credentials.getUsername(),
                credentials.getPassword()
            )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        var token = jwtService.generateToken(credentials.getUsername());
        return ResponseEntity.ok(new AuthResponseDto(token));
    }
}
```

The login handler performs the following:

#### authenticate user credentials

```java
        // authenticate user using authentication provider
        // this internally calls the user-defined UserDetailsService object (not yet defined)
        // to lookup the user details and compares the user-provided credentials to the ones
        // retreived in the lookup.
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                credentials.getUsername(),
                credentials.getPassword()
            )
        );
```

#### add authentication to security context and generate token

```java
        SecurityContextHolder.getContext().setAuthentication(authentication);
        var token = jwtService.generateToken(credentials.getUsername());
        return ResponseEntity.ok(new AuthResponseDto(token));
```

The two dtos involved in the authentication, `AuthResponseDto` and `AuthRequestDto` are defined below:

```java
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class AuthRequestDto {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
```

```java
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class AuthResponseDto {
    private String token;
}
```

When `authenticationManager.authenticate()` is called during login, it calls a user-defined UserDetailsService to load
the user details. Let's define this service bean now.

```java
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import io.onicodes.issue_tracker.models.appUser.AppUser;
import io.onicodes.issue_tracker.repositories.AppUserRepository;
import io.onicodes.issue_tracker.security.AppUserDetails;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class AppUserDetailsService implements UserDetailsService {
    private final AppUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // the 'username' parameter is determined by the principal of the UsernamePasswordAuthenticationToken
        AppUser user = userRepository.findByUsername(username);
        if (user == null)
            throw new UsernameNotFoundException("User not found");

        return new AppUserDetails(user);
    }
}
```

The `username` parameter is determined by the principal of the `UsernamePasswordAuthenticationToken` that was provided
to the `authenticate` method. We provided the principal with `credentials.getUsername()` earlier when creating the
`UsernamePasswordAuthenticationToken` in the login handler, so that's exactly what gets passed here.

With that, the app is secured and ready to use JWT authentication. Here's an example flow:

1. User logs in at the login endpoint

```bash
# request
curl -H "Content-type: application/json" -d '{"username": "<username>", "password": "<password>"}' http://localhost:8080/auth/login

# response
# {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvYmFyb2xsaXMiLCJyb2xlcyI6WyJVU0VSIl0sImlhdCI6MTc0MjU4OTM5MCwiZXhwIjoxNzQyNTkyOTkwfQ.zYdIDfbmEB7nfwe9H2E5qwUYeKIMBsVY0rbJdu0Hz-4"}
```

2. The token is stored locally by the client and used in any subsequent requests to the application

```bash
#  request
curl -H "Content-type: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvYmFyb2xsaXMiLCJyb2xlcyI6WyJVU0VSIl0sImlhdCI6MTc0MjU4OTM5MCwiZXhwIjoxNzQyNTkyOTkwfQ.zYdIDfbmEB7nfwe9H2E5qwUYeKIMBsVY0rbJdu0Hz-4" http://localhost:8080/issues/1

#  response
# {"title":"new issue title","description":"issue description","status":"OPEN","priority":"HIGH","assignees":[],"id":1,"createdAt":"2025-03-21T13:41:37.890272","updatedAt":"2025-03-21T14:05:56.9024288"}
```
