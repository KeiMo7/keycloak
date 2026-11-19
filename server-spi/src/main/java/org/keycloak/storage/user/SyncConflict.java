/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.storage.user;

/**
 * Immutable description of an attribute conflict detected during a federation synchronization.
 */
public class SyncConflict {

    private String userId;
    private String username;
    private String attribute;
    private String directoryValue;
    private String localValue;
    private String resolvedValue;
    private String policy;
    private String winner;
    private String actor;
    private String localModifiedBy;
    private long detectedAt;
    private long localModifiedAt;
    private String directoryModifiedAt;
    private boolean retryable;

    public SyncConflict() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAttribute() {
        return attribute;
    }

    public void setAttribute(String attribute) {
        this.attribute = attribute;
    }

    public String getDirectoryValue() {
        return directoryValue;
    }

    public void setDirectoryValue(String directoryValue) {
        this.directoryValue = directoryValue;
    }

    public String getLocalValue() {
        return localValue;
    }

    public void setLocalValue(String localValue) {
        this.localValue = localValue;
    }

    public String getResolvedValue() {
        return resolvedValue;
    }

    public void setResolvedValue(String resolvedValue) {
        this.resolvedValue = resolvedValue;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public String getWinner() {
        return winner;
    }

    public void setWinner(String winner) {
        this.winner = winner;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getLocalModifiedBy() {
        return localModifiedBy;
    }

    public void setLocalModifiedBy(String localModifiedBy) {
        this.localModifiedBy = localModifiedBy;
    }

    public long getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(long detectedAt) {
        this.detectedAt = detectedAt;
    }

    public long getLocalModifiedAt() {
        return localModifiedAt;
    }

    public void setLocalModifiedAt(long localModifiedAt) {
        this.localModifiedAt = localModifiedAt;
    }

    public String getDirectoryModifiedAt() {
        return directoryModifiedAt;
    }

    public void setDirectoryModifiedAt(String directoryModifiedAt) {
        this.directoryModifiedAt = directoryModifiedAt;
    }

    public boolean isRetryable() {
        return retryable;
    }

    public void setRetryable(boolean retryable) {
        this.retryable = retryable;
    }
}
