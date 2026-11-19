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

package org.keycloak.storage;

import org.keycloak.storage.UserStorageProviderModel.SyncMode;
import org.keycloak.storage.UserStorageProviderModel.SyncStatus;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link UserStorageProviderModel}.
 */
public class UserStorageProviderModelTest {

    @Test
    public void testLegacyLastSyncFallback() {
        UserStorageProviderModel model = new UserStorageProviderModel();
        model.getConfig().putSingle(UserStorageProviderModel.LAST_SYNC, "1600000000");

        // Verify fallback for both CHANGED and FULL sync modes
        assertEquals(1600000000, model.getLastSync(SyncMode.CHANGED));
        assertEquals(1600000000, model.getLastSync(SyncMode.FULL));

        // Verify mode-specific timestamp takes precedence over legacy fallback
        model.setLastSync(1700000000, SyncMode.CHANGED);
        assertEquals(1700000000, model.getLastSync(SyncMode.CHANGED));
        assertEquals(1600000000, model.getLastSync(SyncMode.FULL));
    }

    @Test
    public void testMissingLastSyncReturnsZero() {
        UserStorageProviderModel model = new UserStorageProviderModel();

        assertEquals(0, model.getLastSync(SyncMode.CHANGED));
        assertEquals(0, model.getLastSync(SyncMode.FULL));
    }

    @Test
    public void testNullSyncModeUsesLegacyLastSync() {
        UserStorageProviderModel model = new UserStorageProviderModel();
        model.getConfig().putSingle(UserStorageProviderModel.LAST_SYNC, "1600000000");

        assertEquals(1600000000, model.getLastSync(null));
    }

    @Test
    public void testSyncStateIsPersistedPerMode() {
        UserStorageProviderModel model = new UserStorageProviderModel();

        model.setSyncStatus(SyncMode.FULL, SyncStatus.RUNNING);
        model.setSyncCursor(SyncMode.FULL, "cursor-value");
        model.setSyncProcessed(SyncMode.FULL, 20000);
        model.setSyncTotal(SyncMode.FULL, 100000);
        model.setSyncRemaining(SyncMode.FULL, 80000);
        model.setSyncPhase(SyncMode.FULL, "USERS");
        model.setSyncRunId(SyncMode.FULL, "run-1");
        model.setSyncRetryable(SyncMode.FULL, true);

        assertEquals(SyncStatus.RUNNING, model.getSyncStatus(SyncMode.FULL));
        assertEquals("cursor-value", model.getSyncCursor(SyncMode.FULL));
        assertEquals(20000, model.getSyncProcessed(SyncMode.FULL));
        assertEquals(100000, model.getSyncTotal(SyncMode.FULL));
        assertEquals(80000, model.getSyncRemaining(SyncMode.FULL));
        assertEquals("USERS", model.getSyncPhase(SyncMode.FULL));
        assertEquals("run-1", model.getSyncRunId(SyncMode.FULL));
        assertTrue(model.isSyncRetryable(SyncMode.FULL));

        assertEquals(SyncStatus.IDLE, model.getSyncStatus(SyncMode.CHANGED));
        assertEquals(-1, model.getSyncTotal(SyncMode.CHANGED));
        assertFalse(model.isSyncRetryable(SyncMode.CHANGED));
    }
}
