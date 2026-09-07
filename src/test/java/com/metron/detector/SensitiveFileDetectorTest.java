package com.metron.detector;

import com.metron.client.dto.GitLabTreeItem;
import com.metron.model.Project;
import com.metron.model.Risk;
import com.metron.model.RiskCategory;
import com.metron.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveFileDetectorTest {

    private SensitiveFileDetector detector;
    private Project testProject;

    @BeforeEach
    void setUp() {
        detector = new SensitiveFileDetector();
        testProject = new Project(1L, "demo-repo", "demo-repo", "demo-repo", "Demo Project", "https://gitlab.com/demo", "main", "public");
    }

    @Test
    void testDetectSensitiveFiles_FindsExactMatches() {
        List<GitLabTreeItem> tree = List.of(
                new GitLabTreeItem("1", ".env", "blob", ".env", "100644"),
                new GitLabTreeItem("2", "id_rsa", "blob", "id_rsa", "100644"),
                new GitLabTreeItem("3", "config.json", "blob", "src/config.json", "100644"),
                new GitLabTreeItem("4", "secrets.yml", "blob", "secrets.yml", "100644"),
                new GitLabTreeItem("5", "server.key", "blob", "certs/server.key", "100644"),
                new GitLabTreeItem("6", "cert.pem", "blob", "certs/cert.pem", "100644"),
                new GitLabTreeItem("7", ".pem", "blob", ".pem", "100644"),
                new GitLabTreeItem("8", "Application.java", "blob", "src/Application.java", "100644")
        );

        RepositoryScanContext context = new RepositoryScanContext(testProject, tree, path -> Optional.empty());
        List<Risk> risks = detector.detect(context);

        assertEquals(7, risks.size());
        for (Risk risk : risks) {
            assertEquals(RiskCategory.SENSITIVE_FILE, risk.category());
            assertEquals("Sensitive Files", risk.issue());
            assertEquals(Severity.HIGH, risk.severity());
            assertNotNull(risk.remediation());
        }

        List<String> files = risks.stream().map(Risk::file).toList();
        assertTrue(files.contains(".env"));
        assertTrue(files.contains(".pem"));
        assertTrue(files.contains("id_rsa"));
        assertTrue(files.contains("src/config.json"));
        assertTrue(files.contains("secrets.yml"));
        assertTrue(files.contains("certs/server.key"));
        assertTrue(files.contains("certs/cert.pem"));
        assertFalse(files.contains("src/Application.java"));
    }

    @Test
    void testDetectSensitiveFiles_IgnoresCleanFilesAndDirectories() {
        List<GitLabTreeItem> tree = List.of(
                new GitLabTreeItem("1", "src", "tree", "src", "040000"),
                new GitLabTreeItem("2", "Main.java", "blob", "src/Main.java", "100644"),
                new GitLabTreeItem("3", "pom.xml", "blob", "pom.xml", "100644"),
                new GitLabTreeItem("4", "README.md", "blob", "README.md", "100644")
        );

        RepositoryScanContext context = new RepositoryScanContext(testProject, tree, path -> Optional.empty());
        List<Risk> risks = detector.detect(context);

        assertTrue(risks.isEmpty());
    }
}
