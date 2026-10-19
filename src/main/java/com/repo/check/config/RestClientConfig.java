package com.repo.check.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean
    public RestClient gitLabRestClient(GitLabProperties properties) {
        String baseUrl = properties.baseUrl() != null ? properties.baseUrl().replaceAll("/+$", "") : "https://gitlab.com";
        String apiPath = properties.apiPath() != null ? properties.apiPath() : "/api/v4";
        if (!apiPath.startsWith("/")) {
            apiPath = "/" + apiPath;
        }

        RestClient.Builder clientBuilder = RestClient.builder()
                .baseUrl(baseUrl + apiPath)
                .defaultHeader("Accept", "application/json");

        if (properties.token() != null && !properties.token().isBlank()) {
            clientBuilder.defaultHeader("PRIVATE-TOKEN", properties.token().trim());
        }

        return clientBuilder.build();
    }
}
