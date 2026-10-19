package com.repo.check.detector;

import com.repo.check.client.dto.GitLabTreeItem;
import com.repo.check.model.Risk;
import com.repo.check.model.RiskCategory;
import com.repo.check.model.Severity;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class SensitiveFileDetector implements RiskDetector {

    // Exact filenames that are sensitive (checked in lowercase)
    private static final Set<String> EXACT_SENSITIVE_FILES = Set.of(
            ".env",
            ".pem",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.test",
            ".env.staging",
            "id_rsa",
            "id_dsa",
            "id_ed25519",
            "id_ecdsa",
            "config.json",
            "secrets.yml",
            "secrets.yaml",
            "secret.yml",
            "secret.yaml",
            "credentials.json",
            "credentials.yml",
            "credentials.yaml",
            "service-account.json",
            "serviceaccountkey.json",
            ".htpasswd",
            "docker-compose.override.yml",
            "docker-compose.override.yaml"
    );

    // Extensions that indicate sensitive files/keys/certificates
    private static final Set<String> SENSITIVE_EXTENSIONS = Set.of(
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".pkcs12",
            ".keystore",
            ".jks"
    );

    @Override
    public List<Risk> detect(RepositoryScanContext context) {
        List<Risk> risks = new ArrayList<>();

        for (GitLabTreeItem item : context.tree()) {
            if (item.isTree()) {
                continue; // Only check files/blobs
            }

            String pathStr = item.path();
            if (pathStr == null || pathStr.isBlank()) {
                continue;
            }

            Path path = Paths.get(pathStr);
            String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);

            boolean isSensitive = false;
            String reason = null;

            if (EXACT_SENSITIVE_FILES.contains(fileName)) {
                isSensitive = true;
                reason = "Exact sensitive filename match: " + fileName;
            } else if (fileName.startsWith(".env.")) {
                isSensitive = true;
                reason = "Environment configuration file: " + fileName;
            } else {
                for (String ext : SENSITIVE_EXTENSIONS) {
                    if (fileName.endsWith(ext)) {
                        isSensitive = true;
                        reason = "Sensitive credential / certificate extension (" + ext + "): " + fileName;
                        break;
                    }
                }
            }

            if (isSensitive) {
                risks.add(new Risk(
                        RiskCategory.SENSITIVE_FILE,
                        "Sensitive Files",
                        "Sensitive file committed to repository (" + reason + ")",
                        Severity.HIGH,
                        item.path(),
                        null,
                        null,
                        "Remove the file from Git history using 'git rm --cached " + item.path() + "', add to .gitignore, and revoke/rotate any contained credentials."
                ));
            }
        }

        return risks;
    }
}
