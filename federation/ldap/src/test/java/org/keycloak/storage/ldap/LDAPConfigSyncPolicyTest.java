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
package org.keycloak.storage.ldap;

import org.keycloak.common.util.MultivaluedHashMap;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LDAPConfigSyncPolicyTest {

    @Test
    public void resolvesPriorityPerField() {
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(LDAPConfig.SYNC_ATTRIBUTE_PRIORITIES, "email=DIRECTORY, phone=local");
        LDAPConfig ldapConfig = new LDAPConfig(config);

        assertEquals(LDAPConfig.SYNC_PRIORITY_DIRECTORY, ldapConfig.getSyncAttributePriority("email"));
        assertEquals(LDAPConfig.SYNC_PRIORITY_LOCAL, ldapConfig.getSyncAttributePriority("phone"));
        assertEquals(LDAPConfig.SYNC_PRIORITY_LEGACY, ldapConfig.getSyncAttributePriority("firstName"));
    }

    @Test
    public void deletionAndOwnershipDefaultsPreserveLegacyBehavior() {
        LDAPConfig ldapConfig = new LDAPConfig(new MultivaluedHashMap<>());

        assertEquals(LDAPConfig.SYNC_DELETION_LEGACY, ldapConfig.getSyncDeletionMode());
        assertTrue(ldapConfig.isSyncGroupOwnershipEnabled());

        MultivaluedHashMap<String, String> explicit = new MultivaluedHashMap<>();
        explicit.putSingle(LDAPConfig.SYNC_DELETION_MODE, "disable");
        explicit.putSingle(LDAPConfig.SYNC_GROUP_OWNERSHIP, "false");
        ldapConfig = new LDAPConfig(explicit);
        assertEquals(LDAPConfig.SYNC_DELETION_DISABLE, ldapConfig.getSyncDeletionMode());
        assertFalse(ldapConfig.isSyncGroupOwnershipEnabled());
    }
}
