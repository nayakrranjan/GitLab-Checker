package com.repo.check.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "gitlab")
public record GitLabProperties(
        @DefaultValue("https://gitlab.com") String baseUrl,
        @DefaultValue("/api/v4") String apiPath,
        String token,
        @DefaultValue("524288") int maxFileScanSize,
        @DefaultValue("500") int maxTreeItems
) {
}
