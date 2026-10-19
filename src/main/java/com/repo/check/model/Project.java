package com.repo.check.model;

public record Project(
        Long id,
        String name,
        String path,
        String pathWithNamespace,
        String description,
        String webUrl,
        String defaultBranch,
        String visibility
) {
}