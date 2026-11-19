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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.keycloak.models.UserModel;

/**
 * Names and helpers for the metadata that lets a federation synchronization merge local and directory state.
 *
 * <p>The metadata is stored on the local user, so it survives restarts and does not require a new database schema.
 * The prefix is intentionally not a user-visible profile attribute.</p>
 */
public final class UserSyncMetadata {

    public static final String PREFIX = "kc.sync.";
    public static final String DIRECTORY_BASELINE_PREFIX = PREFIX + "directory.baseline.";
    public static final String LOCAL_MODIFIED_AT_PREFIX = PREFIX + "local.modifiedAt.";
    public static final String LOCAL_MODIFIED_BY_PREFIX = PREFIX + "local.modifiedBy.";
    public static final String AUDIT_PREFIX = PREFIX + "audit.";
    public static final String SEEN_RUN_ATTRIBUTE = PREFIX + "directory.seenRun";
    public static final String DELETED_AT_ATTRIBUTE = PREFIX + "directory.deletedAt";
    public static final String DELETED_BY_ATTRIBUTE = PREFIX + "directory.deletedBy";
    public static final String GROUP_OWNER_ATTRIBUTE = PREFIX + "directory.owner";

    private static final String EMPTY_VALUE = "\u0000";

    private UserSyncMetadata() {
    }

    public static String fieldKey(String field) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(field.getBytes(StandardCharsets.UTF_8));
    }

    public static String baselineAttribute(String field) {
        return DIRECTORY_BASELINE_PREFIX + fieldKey(field);
    }

    public static String localModifiedAtAttribute(String field) {
        return LOCAL_MODIFIED_AT_PREFIX + fieldKey(field);
    }

    public static String localModifiedByAttribute(String field) {
        return LOCAL_MODIFIED_BY_PREFIX + fieldKey(field);
    }

    public static String auditAttribute(String field) {
        return AUDIT_PREFIX + fieldKey(field);
    }

    public static List<String> getBaseline(UserModel user, String field) {
        return decodeValues(user.getAttributeStream(baselineAttribute(field)).toList());
    }

    public static void setBaseline(UserModel user, String field, List<String> values) {
        user.setAttribute(baselineAttribute(field), List.of(encodeValues(values)));
    }

    public static long getLocalModifiedAt(UserModel user, String field) {
        String value = user.getFirstAttribute(localModifiedAtAttribute(field));
        if (value == null) {
            return 0L;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    public static String getLocalModifiedBy(UserModel user, String field) {
        return user.getFirstAttribute(localModifiedByAttribute(field));
    }

    public static void recordLocalChange(UserModel user, String field, String actor, long timestamp) {
        user.setSingleAttribute(localModifiedAtAttribute(field), Long.toString(timestamp));
        if (actor != null && !actor.isBlank()) {
            user.setSingleAttribute(localModifiedByAttribute(field), actor);
        }
    }

    public static Map<String, List<String>> snapshot(UserModel user) {
        Map<String, List<String>> snapshot = new HashMap<>();
        user.getAttributes().forEach((name, values) -> {
            if (!name.startsWith(PREFIX)) {
                snapshot.put(name, new ArrayList<>(values));
            }
        });
        snapshot.put(UserModel.USERNAME, single(user.getUsername()));
        snapshot.put(UserModel.EMAIL, single(user.getEmail()));
        snapshot.put(UserModel.FIRST_NAME, single(user.getFirstName()));
        snapshot.put(UserModel.LAST_NAME, single(user.getLastName()));
        snapshot.put(UserModel.ENABLED, single(Boolean.toString(user.isEnabled())));
        snapshot.put(UserModel.EMAIL_VERIFIED, single(Boolean.toString(user.isEmailVerified())));
        return snapshot;
    }

    public static void recordLocalChanges(UserModel user, Map<String, List<String>> previous, String actor, long timestamp) {
        Map<String, List<String>> current = snapshot(user);
        Set<String> fields = new HashSet<>(previous.keySet());
        fields.addAll(current.keySet());
        for (String field : fields) {
            if (field.startsWith(PREFIX)) {
                continue;
            }
            if (!Objects.equals(normalize(previous.get(field)), normalize(current.get(field)))) {
                recordLocalChange(user, field, actor, timestamp);
            }
        }
    }

    public static String encodeValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return EMPTY_VALUE;
        }
        return String.join("\u0001", values.stream().map(value -> value == null ? EMPTY_VALUE : value).toList());
    }

    public static List<String> decodeValues(List<String> encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return List.of();
        }
        String value = encoded.get(0);
        if (EMPTY_VALUE.equals(value) || value.isEmpty()) {
            return List.of();
        }
        String[] parts = value.split("\u0001", -1);
        List<String> result = new ArrayList<>(parts.length);
        for (String part : parts) {
            result.add(EMPTY_VALUE.equals(part) ? null : part);
        }
        return result;
    }

    public static String normalize(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        return values.stream().map(value -> value == null ? "" : value).sorted().reduce("", (left, right) -> left + "\u0001" + right);
    }

    private static List<String> single(String value) {
        List<String> values = new ArrayList<>(1);
        values.add(value);
        return values;
    }
}
