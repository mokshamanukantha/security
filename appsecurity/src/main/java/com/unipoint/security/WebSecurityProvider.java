package com.unipoint.security;

import java.io.FileInputStream;
import java.net.URL;

import com.google.firebase.auth.FirebaseAuth;
import com.unipoint.security.util.AuthBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;

@Configuration
@ComponentScan("com.unipoint.security")
public class WebSecurityProvider {

    private final AuthBuilder authBuilder;

    public WebSecurityProvider(@Autowired(required = false) AuthBuilder authBuilder) {
        this.authBuilder = authBuilder;
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("POST");
        config.addAllowedHeader("x-firebase-auth");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public FirebaseAuth firebaseAuth() throws Exception {

        URL resource = getClass().getClassLoader().getResource(authBuilder.getFirebaseConfig());
        if(resource!=null) {
            FileInputStream serviceAccount = new FileInputStream(
                    resource.getFile());

            FirebaseOptions options = new FirebaseOptions.Builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .setDatabaseUrl(authBuilder.getFirebaseDb()).build();

            FirebaseApp.initializeApp(options);

            return FirebaseAuth.getInstance();
        }
        throw new Exception("Couldn't create the auth chain !");
    }
}
