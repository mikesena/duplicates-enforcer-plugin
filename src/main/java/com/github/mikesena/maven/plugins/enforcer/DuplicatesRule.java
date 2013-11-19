/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2013 Michael Sena
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.github.mikesena.maven.plugins.enforcer;

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

/**
 * Checks dependencies for classes previously included.
 * 
 * @author Michael Sena
 * 
 */
public class DuplicatesRule implements EnforcerRule {
    private final Map<String, Artifact> entries;
    private final List<Pattern> excludePatterns;
    private String[] excludes;
    private final List<Pattern> includePatterns;
    private String[] includes;
    private Log log;
    private final Map<String, List<Artifact>> problems;
    private MavenProject project;
    private MavenSession session;

    /** Main constructor. */
    public DuplicatesRule() {
        problems = new HashMap<>();
        entries = new HashMap<>();
        includePatterns = new ArrayList<>();
        excludePatterns = new ArrayList<>();
    }

    @Override
    public void execute(final EnforcerRuleHelper helper) throws EnforcerRuleException {
        setup(helper);
        scanProject();
        processResult();
    }

    @Override
    public String getCacheId() {
        return null;
    }

    @Override
    public boolean isCacheable() {
        return false;
    }

    @Override
    public boolean isResultValid(final EnforcerRule arg0) {
        return false;
    }

    /**
     * Extracts out common Maven variables.
     * 
     * @param helper
     *            Helper to extract from.
     * @throws EnforcerRuleException
     *             thrown on a general error. The error is wrapped in this exception, so the Maven build will fail
     *             correctly.
     */
    protected void setup(final EnforcerRuleHelper helper) throws EnforcerRuleException {
        log = helper.getLog();
        try {
            project = (MavenProject) helper.evaluate("${project}");
            session = (MavenSession) helper.evaluate("${session}");
        } catch (final ExpressionEvaluationException e) {
            throw new EnforcerRuleException("Unable to lookup item " + e.getLocalizedMessage(), e);
        }
        if (includes != null) {
            for (final String include : includes) {
                includePatterns.add(Pattern.compile(include));
            }
        }
        if (excludes != null) {
            for (final String exclude : excludes) {
                excludePatterns.add(Pattern.compile(exclude));
            }
        }
    }

    /**
     * Get a list entry for the className.
     * 
     * @param className
     *            (to retrieve)
     * @return the entry
     */
    private List<Artifact> getProblemEntry(final String className) {
        List<Artifact> problemEntry = problems.get(className);
        if (problemEntry == null) {
            problemEntry = new ArrayList<>();
            problemEntry.add(entries.get(className));
            problems.put(className, problemEntry);
        }
        return problemEntry;
    }

    /**
     * Whether a specified class should be excluded.
     * 
     * @param className
     *            (to check)
     * @return class' inclusion
     */
    private boolean isExcluded(final String className) {
        if (excludePatterns.size() == 0) {
            return false;
        } else {
            for (final Pattern pattern : excludePatterns) {
                if (pattern.matcher(className).matches()) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Whether a specified class should be included.
     * 
     * @param className
     *            (to check)
     * @return class' inclusion
     */
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

    /**
     * Scans a Maven dependency, adding its entries to a store.
     * 
     * @param artifactToScan
     *            Input artifact to process
     * @throws EnforcerRuleException
     *             thrown on a general error. The error is wrapped in this exception, so the Maven build will fail
     *             correctly.
     */
    private void processArtifact(final Artifact artifactToScan) throws EnforcerRuleException {
        log.debug("Scanning: " + artifactToScan.toString() + " (" + artifactToScan.getFile() + ")");

        try (JarFile jar = new JarFile(artifactToScan.getFile())) {
            final Enumeration<JarEntry> jarEntries = jar.entries();
            while (jarEntries.hasMoreElements()) {
                final JarEntry entry = jarEntries.nextElement();
                if (entry.getName().endsWith(".class") && shouldBeChecked(entry.getName())) {
                    if (!entries.containsKey(entry.getName())) {
                        entries.put(entry.getName(), artifactToScan);
                    } else {
                        final List<Artifact> problemEntry = getProblemEntry(entry.getName());
                        problemEntry.add(artifactToScan);
                    }
                }
            }
        } catch (final IOException e) {
            throw new EnforcerRuleException("Unable to scan JAR file: " + artifactToScan.getFile().getPath(), e);
        }
    }

    /**
     * Displays the result of the rule, failing if necessary.
     * 
     * @throws EnforcerRuleException
     *             thrown if the rule failed.
     */
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

    /**
     * Scan the Maven project, adding found entries to the list.
     * 
     * @throws EnforcerRuleException
     *             thrown on a general error. The error is wrapped in this exception, so the Maven build will fail
     *             correctly.
     */
    private void scanProject() throws EnforcerRuleException {
        for (final Artifact dependencyArtifact : project.getDependencyArtifacts()) {
            final Artifact artifactToScan = session.getLocalRepository().find(dependencyArtifact);
            processArtifact(artifactToScan);
        }
    }

    /**
     * Whether a specified class is to be checked by the rule.
     * 
     * @param className
     * @return
     */
    private boolean shouldBeChecked(final String className) {
        if (isIncluded(className)) {
            if (!isExcluded(className)) {
                return true;
            }
        }
        return false;
    }
}