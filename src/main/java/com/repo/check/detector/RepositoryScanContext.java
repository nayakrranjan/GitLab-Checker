package com.repo.check.detector;

import com.repo.check.client.dto.GitLabTreeItem;
import com.repo.check.model.Project;

import java.util.List;
import java.util.Optional;

public record RepositoryScanContext(
        Project project,
        List<GitLabTreeItem> tree,
        FileContentProvider contentProvider
) {
    public RepositoryScanContext {
        if (tree == null) {
            tree = List.of();
        }
    }

    public Optional<String> getFileContent(String filePath) {
        return contentProvider != null ? contentProvider.getContent(filePath) : Optional.empty();
    }
}
