/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.representations.idm;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SynchronizationResultRepresentation {

    private boolean ignored;

    private int added;
    private int updated;
    private int removed;
    private int disabled;
    private int failed;
    private int conflicts;
    private int skipped;
    private int retryableFailures;
    private int nonRetryableFailures;
    private int processed;
    private int total = -1;
    private int remaining = -1;
    private boolean retryable;
    private boolean resumed;
    private String phase;
    private String cursor;
    private List<SyncConflictRepresentation> conflictDetails = new ArrayList<>();

    private String status;

    public SynchronizationResultRepresentation() {
    }

    public boolean isIgnored() {
        return ignored;
    }

    public void setIgnored(boolean ignored) {
        this.ignored = ignored;
    }

    public int getAdded() {
        return added;
    }

    public void setAdded(int added) {
        this.added = added;
    }

    public int getUpdated() {
        return updated;
    }

    public void setUpdated(int updated) {
        this.updated = updated;
    }

    public int getRemoved() {
        return removed;
    }

    public void setRemoved(int removed) {
        this.removed = removed;
    }

    public int getDisabled() {
        return disabled;
    }

    public void setDisabled(int disabled) {
        this.disabled = disabled;
    }

    public int getFailed() {
        return failed;
    }

    public void setFailed(int failed) {
        this.failed = failed;
    }

    public int getConflicts() {
        return conflicts;
    }

    public void setConflicts(int conflicts) {
        this.conflicts = conflicts;
    }

    public int getSkipped() {
        return skipped;
    }

    public void setSkipped(int skipped) {
        this.skipped = skipped;
    }

    public int getRetryableFailures() {
        return retryableFailures;
    }

    public void setRetryableFailures(int retryableFailures) {
        this.retryableFailures = retryableFailures;
    }

    public int getNonRetryableFailures() {
        return nonRetryableFailures;
    }

    public void setNonRetryableFailures(int nonRetryableFailures) {
        this.nonRetryableFailures = nonRetryableFailures;
    }

    public int getProcessed() {
        return processed;
    }

    public void setProcessed(int processed) {
        this.processed = processed;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public int getRemaining() {
        return remaining;
    }

    public void setRemaining(int remaining) {
        this.remaining = remaining;
    }

    public boolean isRetryable() {
        return retryable;
    }

    public void setRetryable(boolean retryable) {
        this.retryable = retryable;
    }

    public boolean isResumed() {
        return resumed;
    }

    public void setResumed(boolean resumed) {
        this.resumed = resumed;
    }

    public String getPhase() {
        return phase;
    }

    public void setPhase(String phase) {
        this.phase = phase;
    }

    public String getCursor() {
        return cursor;
    }

    public void setCursor(String cursor) {
        this.cursor = cursor;
    }

    public List<SyncConflictRepresentation> getConflictDetails() {
        return conflictDetails;
    }

    public void setConflictDetails(List<SyncConflictRepresentation> conflictDetails) {
        this.conflictDetails = conflictDetails;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

}
