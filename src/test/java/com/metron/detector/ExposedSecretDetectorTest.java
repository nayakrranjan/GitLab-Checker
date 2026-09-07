package com.metron.detector;

import com.metron.client.dto.GitLabTreeItem;
import com.metron.model.Project;
import com.metron.model.Risk;
import com.metron.model.RiskCategory;
import com.metron.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ExposedSecretDetectorTest {

    private ExposedSecretDetector detector;
    private Project testProject;

    @BeforeEach
    void setUp() {
        detector = new ExposedSecretDetector();
        testProject = new Project(1L, "demo-repo", "demo-repo", "demo-repo", "Demo Project", "https://gitlab.com/demo", "main", "public");
    }

    @Test
    void testDetectAwsAccessKey() {
        String content = """
                # Deployment configuration
                AWS_REGION=us-east-1
                AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
                echo "Deploying..."
                """;

        List<Risk> risks = detector.scanContent("deploy.sh", content);
        assertFalse(risks.isEmpty());

        Risk risk = risks.getFirst();
        assertEquals(RiskCategory.EXPOSED_SECRET, risk.category());
        assertEquals("Exposed Secrets", risk.issue());
        assertEquals(Severity.HIGH, risk.severity());
        assertEquals(3, risk.line());
        assertTrue(risk.description().contains("AWS Access Key ID"));
        // Secret should be masked in the snippet
        assertFalse(risk.snippet().contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(risk.snippet().contains("AKIA"));
        assertTrue(risk.snippet().contains("*"));
    }

    @Test
    void testDetectGitLabToken() {
        String content = "GITLAB_TOKEN=\"glpat-1234567890abcdefghij\"";
        List<Risk> risks = detector.scanContent("config.py", content);

        assertEquals(1, risks.size());
        Risk risk = risks.getFirst();
        assertEquals(Severity.HIGH, risk.severity());
        assertTrue(risk.description().contains("GitLab Personal Access Token"));
        assertTrue(risk.snippet().contains("glpat-"));
    }

    @Test
    void testDetectGitHubToken() {
        String content = "const token = 'ghp_123456789012345678901234567890123456';";
        List<Risk> risks = detector.scanContent("index.js", content);

        assertEquals(1, risks.size());
        Risk risk = risks.getFirst();
        assertTrue(risk.description().contains("GitHub Personal Access Token"));
    }

    @Test
    void testDetectPrivateKeyHeader() {
        String content = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIEowIBAAKCAQEA0Y3y...
                -----END RSA PRIVATE KEY-----
                """;
        List<Risk> risks = detector.scanContent("server.key", content);

        assertFalse(risks.isEmpty());
        assertTrue(risks.stream().anyMatch(r -> r.description().contains("Private Key Header")));
    }

    @Test
    void testDetectDatabaseUriWithCredentials() {
        String content = "DATABASE_URL=postgres://admin:superSecretPassword123@db.internal:5432/production";
        List<Risk> risks = detector.scanContent("app.env", content);

        assertFalse(risks.isEmpty());
        assertTrue(risks.stream().anyMatch(r -> r.description().contains("Database URI Credentials")));
    }

    @Test
    void testDetectInRepositoryContext_SkipsBinaryFiles() {
        Map<String, String> fileContents = new HashMap<>();
        fileContents.put("image.png", "binary_content_AKIAIOSFODNN7EXAMPLE");
        fileContents.put("src/main.py", "API_KEY = ");

        List<GitLabTreeItem> tree = List.of(
                new GitLabTreeItem("1", "image.png", "blob", "image.png", "100644"),
                new GitLabTreeItem("2", "main.py", "blob", "src/main.py", "100644")
        );

        RepositoryScanContext context = new RepositoryScanContext(testProject, tree, path -> Optional.ofNullable(fileContents.get(path)));
        List<Risk> risks = detector.detect(context);

        // image.png should be skipped, main.py should be scanned
        assertEquals(1, risks.size());
        assertEquals("src/main.py", risks.getFirst().file());
    }

    @Test
    void testMaskSecret() {
        String secret = "AKIAIOSFODNN7EXAMPLE";
        String masked = ExposedSecretDetector.maskSecret(secret);
        assertEquals(secret.length(), masked.length());
        assertTrue(masked.startsWith("AKIA"));
        assertTrue(masked.endsWith("MPLE"));
        assertTrue(masked.contains("************"));
    }
}
