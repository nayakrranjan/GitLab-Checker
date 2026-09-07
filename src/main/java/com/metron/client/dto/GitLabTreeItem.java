package com.metron.client.dto;

public record GitLabTreeItem(
        String id,
        String name,
        String type,
        String path,
        String mode
) {
    public boolean isBlob() {
        return "blob".equalsIgnoreCase(type);
    }

    public boolean isTree() {
        return "tree".equalsIgnoreCase(type);
    }
}
