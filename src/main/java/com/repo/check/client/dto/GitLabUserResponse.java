package com.repo.check.client.dto;

public record GitLabUserResponse(
        Long id,
        String username,
        String name
) {
}