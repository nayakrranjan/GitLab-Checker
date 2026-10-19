package com.repo.check.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record GitLabProjectResponse(

        Long id,
        String name,
        String path,

        @JsonProperty("path_with_namespace")
        String pathWithNamespace,

        String description,

        @JsonProperty("web_url")
        String webUrl,

        @JsonProperty("default_branch")
        String defaultBranch,

        String visibility
) {
}