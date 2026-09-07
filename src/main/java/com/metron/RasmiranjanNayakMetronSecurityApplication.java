package com.metron;

import com.metron.config.GitLabProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(GitLabProperties.class)
public class RasmiranjanNayakMetronSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(RasmiranjanNayakMetronSecurityApplication.class, args);
    }

}
