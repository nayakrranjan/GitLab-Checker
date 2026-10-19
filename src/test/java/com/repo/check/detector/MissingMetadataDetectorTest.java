package com.repo.check.detector;

import com.repo.check.client.dto.GitLabTreeItem;
import com.repo.check.model.Project;
import com.repo.check.model.Risk;
import com.repo.check.model.RiskCategory;
import com.repo.check.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class MissingMetadataDetectorTest {

    private MissingMetadataDetector detector;
    private Project testProject;

    @BeforeEach
    void setUp() {
        detector = new MissingMetadataDetector();
        testProject = new Project(1L, "demo-repo", "demo-repo", "demo-repo", "Demo Project", "https://gitlab.com/demo", "main", "public");
    }

    @Test
    void testDetect_MissingBothReadmeAndLicense() {
        List<GitLabTreeItem> tree = List.of(
                new GitLabTreeItem("1", "Main.java", "blob", "src/Main.java", "100644"),
                new GitLabTreeItem("2", "pom.xml", "blob", "pom.xml", "100644")
        );

        RepositoryScanContext context = new RepositoryScanContext(testProject, tree, path -> Optional.empty());
        List<Risk> risks = detector.detect(context);

        assertEquals(2, risks.size());
        for (Risk risk : risks) {
            assertEquals(RiskCategory.MISSING_METADATA, risk.category());
            assertEquals("Missing Metadata", risk.issue());
            assertEquals(Severity.LOW, risk.severity());
        }

        assertTrue(risks.stream().anyMatch(r -> r.file().equals("README.md")));
        assertTrue(risks.stream().anyMatch(r -> r.file().equals("LICENSE")));
    }

    @Test
    void testDetect_HasReadmeOnly() {
        List<GitLabTreeItem> tree = List.of(
                new GitLabTreeItem("1", "README.md", "blob", "README.md", "100644"),
                new GitLabTreeItem("2", "pom.xml", "blob", "pom.xml", "100644")
        );

        RepositoryScanContext context = new RepositoryScanContext(testProject, tree, path -> Optional.empty());
        List<Risk> risks = detector.detect(context);

        assertEquals(1, risks.size());
        assertEquals("LICENSE", risks.getFirst().file());
    }

    @Test
    void testDetect_HasBothReadmeAndLicense_NoRisks() {
        List<GitLabTreeItem> tree = List.of(
                new GitLabTreeItem("1", "README.md", "blob", "README.md", "100644"),
                new GitLabTreeItem("2", "LICENSE", "blob", "LICENSE", "100644")
        );

        RepositoryScanContext context = new RepositoryScanContext(testProject, tree, path -> Optional.empty());
        List<Risk> risks = detector.detect(context);

        assertTrue(risks.isEmpty());
    }
}
