package com.repo.check.detector;

import com.repo.check.client.dto.GitLabTreeItem;
import com.repo.check.model.Risk;
import com.repo.check.model.RiskCategory;
import com.repo.check.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class MissingMetadataDetector implements RiskDetector {

    private static final Set<String> KNOWN_README_NAMES = Set.of(
            "readme.md",
            "readme",
            "readme.txt",
            "readme.rst",
            "readme.markdown"
    );

    private static final Set<String> KNOWN_LICENSE_NAMES = Set.of(
            "license",
            "license.md",
            "license.txt",
            "licence",
            "licence.md",
            "licence.txt",
            "copying",
            "unlicense"
    );

    @Override
    public List<Risk> detect(RepositoryScanContext context) {
        List<Risk> risks = new ArrayList<>();

        boolean hasReadme = false;
        boolean hasLicense = false;

        for (GitLabTreeItem item : context.tree()) {
            if (item.isTree()) {
                continue;
            }

            String path = item.path();
            if (path == null) {
                continue;
            }

            // We check files located in the root directory (no slash)
            if (!path.contains("/")) {
                String lowerName = path.toLowerCase(Locale.ROOT);
                if (KNOWN_README_NAMES.contains(lowerName)) {
                    hasReadme = true;
                }
                if (KNOWN_LICENSE_NAMES.contains(lowerName)) {
                    hasLicense = true;
                }
            }
        }

        if (!hasReadme) {
            risks.add(new Risk(
                    RiskCategory.MISSING_METADATA,
                    "Missing Metadata",
                    "Missing README.md file in repository root",
                    Severity.LOW,
                    "README.md",
                    null,
                    null,
                    "Add a comprehensive README.md file describing project purpose, architecture, and setup instructions."
            ));
        }

        if (!hasLicense) {
            risks.add(new Risk(
                    RiskCategory.MISSING_METADATA,
                    "Missing Metadata",
                    "Missing LICENSE file in repository root",
                    Severity.LOW,
                    "LICENSE",
                    null,
                    null,
                    "Add an open source or proprietary LICENSE file to clarify copyright and usage permissions."
            ));
        }

        return risks;
    }
}
