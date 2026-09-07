package com.metron.detector;

import com.metron.model.Project;
import com.metron.model.Risk;

import java.util.List;
import java.util.Optional;

public interface RiskDetector {

    default List<Risk> detect(Project project) {
        return detect(new RepositoryScanContext(project, List.of(), path -> Optional.empty()));
    }

    List<Risk> detect(RepositoryScanContext context);
}
