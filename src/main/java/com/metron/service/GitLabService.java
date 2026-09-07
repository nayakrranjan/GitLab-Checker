package com.metron.service;

import com.metron.client.GitLabClient;
import com.metron.client.dto.GitLabProjectResponse;
import com.metron.client.dto.GitLabTreeItem;
import com.metron.client.dto.GitLabUserResponse;
import com.metron.config.GitLabProperties;
import com.metron.detector.FileContentProvider;
import com.metron.model.Project;
import com.metron.model.ScanRequest;
import com.metron.model.ScanType;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class GitLabService {

    private static final Logger log = LoggerFactory.getLogger(GitLabService.class);

    private final GitLabClient gitLabClient;
    private final GitLabProperties properties;

    public List<Project> getUserProjects(String username) {
        return getUserProjects(username, true, null, null);
    }

    public List<Project> getUserProjects(String username, boolean publicOnly, String baseUrl, String token) {
        List<GitLabUserResponse> users = gitLabClient.findUser(username, baseUrl, token);

        if (users.isEmpty()) {
            throw new IllegalArgumentException("GitLab user not found: " + username);
        }

        Long userId = users.getFirst().id();
        return gitLabClient
                .getUserProjects(userId, publicOnly, baseUrl, token)
                .stream()
                .map(this::toProject)
                .toList();
    }

    public List<Project> getGroupProjects(String group) {
        return getGroupProjects(group, true, null, null);
    }

    public List<Project> getGroupProjects(String group, boolean publicOnly, String baseUrl, String token) {
        List<GitLabProjectResponse> projects = gitLabClient.getGroupProjects(group, publicOnly, baseUrl, token);
        return projects.stream()
                .map(this::toProject)
                .toList();
    }

    public Optional<Project> getProject(String projectPathOrId, String baseUrl, String token) {
        return gitLabClient.getProject(projectPathOrId, baseUrl, token)
                .map(this::toProject);
    }

    public List<Project> resolveProjects(ScanRequest request) {
        String target = request.target();
        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("Scan target (username, group, or project) must not be empty.");
        }
        target = target.trim();

        ScanType type = request.effectiveType();
        boolean publicOnly = request.isPublicOnly();
        String baseUrl = request.baseUrl();
        String token = request.token();

        switch (type) {
            case USER -> {
                return getUserProjects(target, publicOnly, baseUrl, token);
            }
            case GROUP -> {
                List<Project> groupProjects = getGroupProjects(target, publicOnly, baseUrl, token);
                if (groupProjects.isEmpty()) {
                    throw new IllegalArgumentException("No repositories found for GitLab group: " + target);
                }
                return groupProjects;
            }
            case PROJECT -> {
                return getProject(target, baseUrl, token)
                        .map(List::of)
                        .orElseThrow(() -> new IllegalArgumentException("GitLab project not found: " + request.target()));
            }
            case AUTO -> {
                // Try as user first
                List<GitLabUserResponse> users = gitLabClient.findUser(target, baseUrl, token);
                if (!users.isEmpty()) {
                    log.info("Resolved '{}' as GitLab user (ID: {})", target, users.getFirst().id());
                    return gitLabClient.getUserProjects(users.getFirst().id(), publicOnly, baseUrl, token)
                            .stream()
                            .map(this::toProject)
                            .toList();
                }

                // If not user, try as group
                List<GitLabProjectResponse> groupProjects = gitLabClient.getGroupProjects(target, publicOnly, baseUrl, token);
                if (!groupProjects.isEmpty()) {
                    log.info("Resolved '{}' as GitLab group (found {} projects)", target, groupProjects.size());
                    return groupProjects.stream()
                            .map(this::toProject)
                            .toList();
                }

                // If contains slash or numeric, try as single project
                if (target.contains("/") || target.matches("^\\d+$")) {
                    Optional<GitLabProjectResponse> project = gitLabClient.getProject(target, baseUrl, token);
                    if (project.isPresent()) {
                        log.info("Resolved '{}' as single GitLab project", target);
                        return List.of(toProject(project.get()));
                    }
                }

                throw new IllegalArgumentException("Could not find any GitLab user, group, or repository matching: '" + target + "'");
            }
        }
        return List.of();
    }

    public List<GitLabTreeItem> getRepositoryTree(Project project, String baseUrl, String token) {
        if (project.id() == null) {
            return List.of();
        }
        int maxItems = Math.max(1, properties.maxTreeItems());
        return gitLabClient.getRepositoryTree(project.id(), project.defaultBranch(), maxItems, baseUrl, token);
    }

    public FileContentProvider getFileContentProvider(Project project, String baseUrl, String token) {
        Map<String, Optional<String>> cache = new ConcurrentHashMap<>();
        return filePath -> cache.computeIfAbsent(filePath, path ->
                gitLabClient.getRawFileContent(project.id(), path, project.defaultBranch(), baseUrl, token)
        );
    }

    private Project toProject(GitLabProjectResponse response) {
        return new Project(
                response.id(),
                response.name(),
                response.path(),
                response.pathWithNamespace() != null ? response.pathWithNamespace() : response.path(),
                response.description(),
                response.webUrl(),
                response.defaultBranch(),
                response.visibility()
        );
    }
}
