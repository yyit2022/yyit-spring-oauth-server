package com.yyit.oauth.server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *
 * </p>
 *
 * @author yanpingping
 * @date 2022/4/13
 **/

@Configuration
public class PasswordEncoderConfiguration {

    @Bean
    public static PasswordEncoder encoder() {
        var defaultEncoder = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>(11);
        encoders.put( "bcrypt", new BCryptPasswordEncoder() );
        encoders.put( "scrypt", new SCryptPasswordEncoder() );
        encoders.put( "argon2", new Argon2PasswordEncoder() );

        return new DelegatingPasswordEncoder( defaultEncoder, encoders );
    }


}
