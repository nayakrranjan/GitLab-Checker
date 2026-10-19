package com.repo.check;

import com.repo.check.config.GitLabProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(GitLabProperties.class)
public class GitLabCheckerApplication {

    public static void main(String[] args) {
        SpringApplication.run(GitLabCheckerApplication.class, args);
    }

}
