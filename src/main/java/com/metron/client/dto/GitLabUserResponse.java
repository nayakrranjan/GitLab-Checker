package com.metron.client.dto;

public record GitLabUserResponse(
        Long id,
        String username,
        String name
) {
}