package com.repo.check.service;

import com.repo.check.detector.RiskDetector;
import com.repo.check.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanServiceTest {

    @Mock
    private GitLabService gitLabService;

    @Mock
    private RiskDetector sensitiveFileDetector;

    @Mock
    private RiskDetector exposedSecretDetector;

    @Mock
    private RiskDetector missingMetadataDetector;

    private ScanService scanService;
    private PdfReportGenerator pdfReportGenerator;

    @BeforeEach
    void setUp() {
        pdfReportGenerator = new PdfReportGenerator();
        scanService = new ScanService(
                gitLabService,
                List.of(sensitiveFileDetector, exposedSecretDetector, missingMetadataDetector),
                pdfReportGenerator
        );
    }

    @Test
    void testScan_AggregatesRisksAcrossRepositories() {
        Project project1 = new Project(1L, "Project1", "project1", "group/project1", "Repo 1", "https://gitlab.com/group/project1", "main", "public");
        Project project2 = new Project(2L, "Project2", "project2", "group/project2", "Repo 2", "https://gitlab.com/group/project2", "main", "public");
        Project project3 = new Project(3L, "Project3", "project3", "group/project3", "Repo 3", "https://gitlab.com/group/project3", "main", "public");

        when(gitLabService.resolveProjects(any())).thenReturn(List.of(project1, project2, project3));
        when(gitLabService.getRepositoryTree(any(), any(), any())).thenReturn(List.of());
        when(gitLabService.getFileContentProvider(any(), any(), any())).thenReturn(path -> java.util.Optional.empty());

        // Configure mock detectors to produce the exact problem statement example:
        // Project1 | Sensitive Files | High
        // Project2 | Exposed Secrets | Medium
        // Project3 | Missing Metadata | Low
        when(sensitiveFileDetector.detect(any(com.repo.check.detector.RepositoryScanContext.class))).thenAnswer(inv -> {
            com.repo.check.detector.RepositoryScanContext ctx = inv.getArgument(0);
            if (ctx.project().name().equals("Project1")) {
                return List.of(new Risk(RiskCategory.SENSITIVE_FILE, "Sensitive Files", "Found .env", Severity.HIGH, ".env"));
            }
            return List.of();
        });

        when(exposedSecretDetector.detect(any(com.repo.check.detector.RepositoryScanContext.class))).thenAnswer(inv -> {
            com.repo.check.detector.RepositoryScanContext ctx = inv.getArgument(0);
            if (ctx.project().name().equals("Project2")) {
                return List.of(new Risk(RiskCategory.EXPOSED_SECRET, "Exposed Secrets", "Generic API Key", Severity.MEDIUM, "config.js"));
            }
            return List.of();
        });

        when(missingMetadataDetector.detect(any(com.repo.check.detector.RepositoryScanContext.class))).thenAnswer(inv -> {
            com.repo.check.detector.RepositoryScanContext ctx = inv.getArgument(0);
            if (ctx.project().name().equals("Project3")) {
                return List.of(new Risk(RiskCategory.MISSING_METADATA, "Missing Metadata", "No README", Severity.LOW, "README.md"));
            }
            return List.of();
        });

        ScanRequest request = new ScanRequest("test-target");
        ScanResponse response = scanService.scan(request);

        assertNotNull(response);
        assertEquals(3, response.totalProjectsScanned());
        assertEquals(3, response.totalRisksFound());
        assertEquals(1, response.highSeverityCount());
        assertEquals(1, response.mediumSeverityCount());
        assertEquals(1, response.lowSeverityCount());

        // Verify CLI Table contains required columns & rows from problem statement
        String cliTable = response.toCliTable();
        assertTrue(cliTable.contains("Project Name"));
        assertTrue(cliTable.contains("Issue"));
        assertTrue(cliTable.contains("Severity"));
        assertTrue(cliTable.contains("Project1"));
        assertTrue(cliTable.contains("Sensitive Files"));
        assertTrue(cliTable.contains("High"));
        assertTrue(cliTable.contains("Project2"));
        assertTrue(cliTable.contains("Exposed Secrets"));
        assertTrue(cliTable.contains("Medium"));
        assertTrue(cliTable.contains("Project3"));
        assertTrue(cliTable.contains("Missing Metadata"));
        assertTrue(cliTable.contains("Low"));
    }

    @Test
    void testExportJsonAndPdf() throws IOException {
        Project project = new Project(1L, "sample-repo", "sample-repo", "user/sample-repo", "Sample", "https://gitlab.com/sample", "main", "public");
        Risk risk = new Risk(RiskCategory.SENSITIVE_FILE, "Sensitive Files", "Found id_rsa", Severity.HIGH, "id_rsa");
        ProjectScanResult psr = new ProjectScanResult(project, List.of(risk));

        ScanResponse response = new ScanResponse("sample-target", ScanType.USER, List.of(psr));

        // Test JSON Export
        String json = scanService.exportJson(response);
        assertNotNull(json);
        assertTrue(json.contains("\"sample-target\""));
        assertTrue(json.contains("\"SENSITIVE_FILE\""));
        assertTrue(json.contains("\"id_rsa\""));

        // Test PDF Export
        byte[] pdfBytes = scanService.exportPdf(response);
        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 100);
        String header = new String(pdfBytes, 0, 8);
        assertTrue(header.startsWith("%PDF-1.4"));
    }
}
