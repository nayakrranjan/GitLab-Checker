package com.repo.check.controller;

import com.repo.check.model.Project;
import com.repo.check.model.ProjectScanResult;
import com.repo.check.model.Risk;
import com.repo.check.model.RiskCategory;
import com.repo.check.model.ScanResponse;
import com.repo.check.model.ScanType;
import com.repo.check.model.Severity;
import com.repo.check.service.GitLabService;
import com.repo.check.service.ScanService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class ScanControllerTest {

    private MockMvc mockMvc;

    @Mock
    private ScanService scanService;

    @Mock
    private GitLabService gitLabService;

    @BeforeEach
    void setUp() {
        ScanController controller = new ScanController(scanService, gitLabService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void testScanPost() throws Exception {
        Project project = new Project(10L, "test-repo", "test-repo", "group/test-repo", "Desc", "https://gitlab.com/test", "main", "public");
        Risk risk = new Risk(RiskCategory.SENSITIVE_FILE, "Sensitive Files", "Found .env", Severity.HIGH, ".env");
        ProjectScanResult psr = new ProjectScanResult(project, List.of(risk));
        ScanResponse response = new ScanResponse("group", ScanType.GROUP, List.of(psr));

        when(scanService.scan(any(com.repo.check.model.ScanRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/v1/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"group\",\"type\":\"GROUP\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.target").value("group"))
                .andExpect(jsonPath("$.totalProjectsScanned").value(1))
                .andExpect(jsonPath("$.highSeverityCount").value(1));
    }

    @Test
    void testScanGet() throws Exception {
        Project project = new Project(10L, "test-repo", "test-repo", "group/test-repo", "Desc", "https://gitlab.com/test", "main", "public");
        ScanResponse response = new ScanResponse("myuser", ScanType.USER, List.of(new ProjectScanResult(project, List.of())));

        when(scanService.scan(any(com.repo.check.model.ScanRequest.class))).thenReturn(response);

        mockMvc.perform(get("/api/v1/scan?target=myuser&type=USER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.target").value("myuser"))
                .andExpect(jsonPath("$.totalProjectsScanned").value(1));
    }

    @Test
    void testScanTableEndpoint() throws Exception {
        Project project = new Project(10L, "Project1", "project1", "group/project1", "Desc", "https://gitlab.com/test", "main", "public");
        Risk risk = new Risk(RiskCategory.SENSITIVE_FILE, "Sensitive Files", "Found .env", Severity.HIGH, ".env");
        ProjectScanResult psr = new ProjectScanResult(project, List.of(risk));
        ScanResponse response = new ScanResponse("group", ScanType.AUTO, List.of(psr));

        when(scanService.scan(any(com.repo.check.model.ScanRequest.class))).thenReturn(response);

        mockMvc.perform(get("/api/v1/scan/table?target=group"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Project Name")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Sensitive Files")));
    }

    @Test
    void testExportPdfEndpoint() throws Exception {
        Project project = new Project(10L, "Project1", "project1", "group/project1", "Desc", "https://gitlab.com/test", "main", "public");
        ScanResponse response = new ScanResponse("group", ScanType.AUTO, List.of(new ProjectScanResult(project, List.of())));

        when(scanService.scan(any(com.repo.check.model.ScanRequest.class))).thenReturn(response);
        when(scanService.exportPdf(any())).thenReturn("%PDF-1.4 mock content".getBytes());

        mockMvc.perform(get("/api/v1/scan/export/pdf?target=group"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-report-group.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    void testHealthEndpoint() throws Exception {
        MockMvc healthMockMvc = MockMvcBuilders.standaloneSetup(new HealthController()).build();
        healthMockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("GitLab Risk Scanner is running"));
    }
}
