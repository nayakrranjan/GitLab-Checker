package com.repo.check.client;

import com.repo.check.client.dto.GitLabProjectResponse;
import com.repo.check.client.dto.GitLabTreeItem;
import com.repo.check.client.dto.GitLabUserResponse;
import com.repo.check.config.GitLabProperties;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
public class GitLabClient {

    private static final Logger log = LoggerFactory.getLogger(GitLabClient.class);

    private final RestClient defaultRestClient;
    private final GitLabProperties properties;
    private final ConcurrentHashMap<String, RestClient> customClients = new ConcurrentHashMap<>();

    private RestClient resolveClient(String customBaseUrl, String customToken) {
        if ((customBaseUrl == null || customBaseUrl.isBlank()) && (customToken == null || customToken.isBlank())) {
            return defaultRestClient;
        }

        final String effectiveBaseUrl = (customBaseUrl != null && !customBaseUrl.isBlank())
                ? customBaseUrl.replaceAll("/+$", "")
                : properties.baseUrl().replaceAll("/+$", "");
        final String effectiveApiPath = (properties.apiPath() != null && properties.apiPath().startsWith("/"))
                ? properties.apiPath()
                : "/" + (properties.apiPath() != null ? properties.apiPath() : "api/v4");
        final String token = (customToken != null && !customToken.isBlank())
                ? customToken.trim()
                : (properties.token() != null ? properties.token().trim() : "");
        String cacheKey = effectiveBaseUrl + effectiveApiPath + ":" + token;

        return customClients.computeIfAbsent(cacheKey, key -> {
            RestClient.Builder builder = RestClient.builder()
                    .baseUrl(effectiveBaseUrl + effectiveApiPath)
                    .defaultHeader("Accept", "application/json");
            if (!token.isBlank()) {
                builder.defaultHeader("PRIVATE-TOKEN", token);
            }
            return builder.build();
        });
    }

    public List<GitLabUserResponse> findUser(String username, String customBaseUrl, String customToken) {
        RestClient client = resolveClient(customBaseUrl, customToken);
        try {
            List<GitLabUserResponse> users = client
                    .get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/users")
                            .queryParam("username", username)
                            .build())
                    .retrieve()
                    .body(new ParameterizedTypeReference<>() {});
            return users != null ? users : List.of();
        } catch (Exception e) {
            log.warn("Failed to find GitLab user '{}': {}", username, e.getMessage());
            return List.of();
        }
    }

    public List<GitLabUserResponse> findUser(String username) {
        return findUser(username, null, null);
    }

    public List<GitLabProjectResponse> getUserProjects(Long userId, boolean publicOnly, String customBaseUrl, String customToken) {
        RestClient client = resolveClient(customBaseUrl, customToken);
        List<GitLabProjectResponse> projects = new ArrayList<>();
        int page = 1;

        while (true) {
            final int currentPage = page;
            try {
                List<GitLabProjectResponse> response = client
                        .get()
                        .uri(uriBuilder -> {
                            var builder = uriBuilder
                                    .path("/users/{userId}/projects")
                                    .queryParam("page", currentPage)
                                    .queryParam("per_page", 100);
                            if (publicOnly) {
                                builder.queryParam("visibility", "public");
                            }
                            return builder.build(userId);
                        })
                        .retrieve()
                        .body(new ParameterizedTypeReference<>() {});

                if (response == null || response.isEmpty()) {
                    break;
                }

                projects.addAll(response);

                if (response.size() < 100) {
                    break;
                }
                page++;
            } catch (Exception e) {
                log.warn("Error fetching projects for user ID {}: {}", userId, e.getMessage());
                break;
            }
        }

        return projects;
    }

    public List<GitLabProjectResponse> getUserProjects(Long userId) {
        return getUserProjects(userId, true, null, null);
    }

    public List<GitLabProjectResponse> getGroupProjects(String group, boolean publicOnly, String customBaseUrl, String customToken) {
        RestClient client = resolveClient(customBaseUrl, customToken);
        List<GitLabProjectResponse> projects = new ArrayList<>();
        int page = 1;

        while (true) {
            final int currentPage = page;
            try {
                List<GitLabProjectResponse> response = client
                        .get()
                        .uri(uriBuilder -> {
                            var builder = uriBuilder
                                    .path("/groups/{group}/projects")
                                    .queryParam("page", currentPage)
                                    .queryParam("per_page", 100)
                                    .queryParam("include_subgroups", true);
                            if (publicOnly) {
                                builder.queryParam("visibility", "public");
                            }
                            return builder.build(group);
                        })
                        .retrieve()
                        .body(new ParameterizedTypeReference<>() {});

                if (response == null || response.isEmpty()) {
                    break;
                }

                projects.addAll(response);

                if (response.size() < 100) {
                    break;
                }
                page++;
            } catch (Exception e) {
                log.warn("Error fetching group projects for group '{}': {}", group, e.getMessage());
                break;
            }
        }

        return projects;
    }

    public List<GitLabProjectResponse> getGroupProjects(String group) {
        return getGroupProjects(group, true, null, null);
    }

    public Optional<GitLabProjectResponse> getProject(String projectPathOrId, String customBaseUrl, String customToken) {
        RestClient client = resolveClient(customBaseUrl, customToken);
        try {
            GitLabProjectResponse response = client
                    .get()
                    // RestClient encodes URI variables. Pre-encoding here produces %252F for namespace paths.
                    .uri("/projects/{id}", projectPathOrId)
                    .retrieve()
                    .body(GitLabProjectResponse.class);
            return Optional.ofNullable(response);
        } catch (Exception e) {
            log.warn("Project not found: '{}' ({})", projectPathOrId, e.getMessage());
            return Optional.empty();
        }
    }

    public List<GitLabTreeItem> getRepositoryTree(Long projectId, String ref, int maxItems, String customBaseUrl, String customToken) {
        RestClient client = resolveClient(customBaseUrl, customToken);
        List<GitLabTreeItem> treeItems = new ArrayList<>();
        int page = 1;

        while (treeItems.size() < maxItems) {
            final int currentPage = page;
            try {
                List<GitLabTreeItem> pageItems = client
                        .get()
                        .uri(uriBuilder -> {
                            var builder = uriBuilder
                                    .path("/projects/{id}/repository/tree")
                                    .queryParam("recursive", true)
                                    .queryParam("page", currentPage)
                                    .queryParam("per_page", 100);
                            if (ref != null && !ref.isBlank()) {
                                builder.queryParam("ref", ref);
                            }
                            return builder.build(projectId);
                        })
                        .retrieve()
                        .onStatus(HttpStatusCode::is4xxClientError, (req, resp) -> {
                            // Handled by returning empty/breaking
                        })
                        .body(new ParameterizedTypeReference<>() {});

                if (pageItems == null || pageItems.isEmpty()) {
                    break;
                }

                int remaining = maxItems - treeItems.size();
                treeItems.addAll(pageItems.subList(0, Math.min(pageItems.size(), remaining)));

                if (pageItems.size() < 100 || treeItems.size() >= maxItems) {
                    break;
                }
                page++;
            } catch (Exception e) {
                log.warn("Error fetching repository tree for project ID {}: {}", projectId, e.getMessage());
                break;
            }
        }

        return treeItems;
    }

    public Optional<String> getRawFileContent(Long projectId, String filePath, String ref, String customBaseUrl, String customToken) {
        RestClient client = resolveClient(customBaseUrl, customToken);
        try {
            String content = client
                    .get()
                    .uri(uriBuilder -> {
                        var builder = uriBuilder
                                .path("/projects/{id}/repository/files/{path}/raw");
                        if (ref != null && !ref.isBlank()) {
                            builder.queryParam("ref", ref);
                        }
                        return builder.build(projectId, filePath);
                    })
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, (req, resp) -> {})
                    .body(String.class);

            return Optional.ofNullable(content);
        } catch (Exception e) {
            log.debug("Could not fetch raw content for project {} file '{}': {}", projectId, filePath, e.getMessage());
            return Optional.empty();
        }
    }
}
