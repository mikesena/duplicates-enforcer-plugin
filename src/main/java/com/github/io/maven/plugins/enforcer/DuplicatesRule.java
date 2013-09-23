package com.github.io.maven.plugins.enforcer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.enforcer.rule.api.EnforcerRule;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.enforcer.rule.api.EnforcerRuleHelper;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;

public class DuplicatesRule implements EnforcerRule {
    private Log log;
    private MavenSession session;
    private MavenProject project;
    private final Map<String, List<Artifact>> problems;
    private final Map<String, Artifact> entries;
    private String[] includes;
    private List<Pattern> includePatterns;

    public DuplicatesRule() {
        problems = new HashMap<>();
        entries = new HashMap<>();
        includePatterns = new ArrayList<>();
    }

    public void execute(final EnforcerRuleHelper helper) throws EnforcerRuleException {
        setup(helper);
        scanProject();
        processResult();
    }

    private void scanProject() throws EnforcerRuleException {
        for (final Artifact dependencyArtifact : project.getDependencyArtifacts()) {
            final Artifact artifactToScan = session.getLocalRepository().find(dependencyArtifact);
            processArtifact(artifactToScan);
        }
    }

    private void processResult() throws EnforcerRuleException {
        if (problems.size() == 0) {
            return;
        }
        for (final String className : problems.keySet()) {
            final List<Artifact> jars = problems.get(className);
            log.info("Duplicate: " + className + " found in " + jars.size() + " jars:");
            for (final Artifact jar : jars) {
                log.info("\t - " + jar.toString());
            }
        }
        throw new EnforcerRuleException("Found: " + problems.size() + " violation(s).");
    }

    private void setup(final EnforcerRuleHelper helper) throws EnforcerRuleException {
        log = helper.getLog();
        try {
            project = (MavenProject) helper.evaluate("${project}");
            session = (MavenSession) helper.evaluate("${session}");
        } catch (ExpressionEvaluationException e) {
            throw new EnforcerRuleException("Unable to lookup item " + e.getLocalizedMessage(), e);
        }

        if (includes != null) {
            for (final String include : includes) {
                includePatterns.add(Pattern.compile(include));
            }
        }
    }

    private void processArtifact(final Artifact artifactToScan) throws EnforcerRuleException {
        log.debug("Scanning: " + artifactToScan.toString() + " (" + artifactToScan.getFile() + ")");

        try (JarFile jar = new JarFile(artifactToScan.getFile())) {
            final Enumeration<JarEntry> jarEntries = jar.entries();
            while (jarEntries.hasMoreElements()) {
                final JarEntry entry = jarEntries.nextElement();
                if (entry.getName().endsWith(".class") && isIncluded(entry.getName())) {
                    if (!entries.containsKey(entry.getName())) {
                        entries.put(entry.getName(), artifactToScan);
                    } else {
                        final List<Artifact> problemEntry = getProblemEntry(entry.getName());
                        problemEntry.add(artifactToScan);
                    }
                }
            }
        } catch (IOException e) {
            throw new EnforcerRuleException("Unable to scan JAR file: " + artifactToScan.getFile().getPath(), e);
        }
    }

    private boolean isIncluded(final String className) {
        if (includePatterns.size() == 0) {
            return true;
        } else {
            for (final Pattern pattern : includePatterns) {
                if (pattern.matcher(className).matches()) {
                    return true;
                }
            }
            return false;
        }
    }

    private List<Artifact> getProblemEntry(final String className) {
        List<Artifact> problemEntry = problems.get(className);
        if (problemEntry == null) {
            problemEntry = new ArrayList<>();
            problemEntry.add(entries.get(className));
            problems.put(className, problemEntry);
        }
        return problemEntry;
    }

    public boolean isCacheable() {
        return false;
    }

    public boolean isResultValid(EnforcerRule arg0) {
        return false;
    }

    @Override
    public String getCacheId() {
        return null;
    }
}