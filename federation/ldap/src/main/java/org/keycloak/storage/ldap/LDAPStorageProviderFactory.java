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

package org.keycloak.storage.ldap;

import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.spi.NamingManager;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.config.MetricsOptions;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.federation.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.federation.kerberos.impl.KerberosUsernamePasswordAuthenticator;
import org.keycloak.federation.kerberos.impl.SPNEGOAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.resources.admin.ComponentResource;
import org.keycloak.storage.StorageUnavailableException;
import org.keycloak.storage.UserStoragePrivateUtil;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.UserStorageProviderModel.SyncMode;
import org.keycloak.storage.UserStorageProviderModel.SyncStatus;
import org.keycloak.storage.UserStorageUtil;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPUtil;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;
import org.keycloak.storage.ldap.mappers.FullNameLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.FullNameLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.HardcodedLDAPAttributeMapper;
import org.keycloak.storage.ldap.mappers.HardcodedLDAPAttributeMapperFactory;
import org.keycloak.storage.ldap.mappers.KerberosPrincipalAttributeMapperFactory;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;
import org.keycloak.storage.ldap.mappers.LDAPMappersComparator;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.msad.MSADUserAccountControlStorageMapper;
import org.keycloak.storage.ldap.mappers.msad.MSADUserAccountControlStorageMapperFactory;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SyncConflict;
import org.keycloak.storage.user.SynchronizationResult;
import org.keycloak.storage.user.UserSyncMetadata;
import org.keycloak.utils.CredentialHelper;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class LDAPStorageProviderFactory implements UserStorageProviderFactory<LDAPStorageProvider>, ImportSynchronization {


    private static final Logger logger = Logger.getLogger(LDAPStorageProviderFactory.class);
    public static final String PROVIDER_NAME = LDAPConstants.LDAP_PROVIDER;
    private static final String LDAP_CONNECTION_POOL_PROTOCOL = "com.sun.jndi.ldap.connect.pool.protocol";
    private static final String SECURE_REFERRAL = "secureReferral";
    private static final boolean SECURE_REFERRAL_DEFAULT = true;

    private static final String METRICS_ENABLED = "metricsEnabled";
    private LDAPIdentityStoreRegistry ldapStoreRegistry;
    private Meter.MeterProvider<Timer> ldapRequestTimer; // null when disabled
    private boolean disableKerberosAuthenticationRoundTrip;

    protected static final List<ProviderConfigProperty> configProperties;

    static {
        configProperties = getConfigProps(null);
    }

    private static List<ProviderConfigProperty> getConfigProps(ComponentModel parent) {
        boolean readOnly = false;
        if (parent != null) {
            LDAPConfig config = new LDAPConfig(parent.getConfig());
            readOnly = config.getEditMode() != UserStorageProvider.EditMode.WRITABLE;
        }


        return ProviderConfigurationBuilder.create()
                .property().name(LDAPConstants.EDIT_MODE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(UserStorageProviderModel.IMPORT_ENABLED)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property().name(LDAPConstants.SYNC_REGISTRATIONS)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(LDAPConstants.VENDOR)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.USE_PASSWORD_MODIFY_EXTENDED_OP)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .add()
                .property().name(LDAPConstants.USERNAME_LDAP_ATTRIBUTE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.RDN_LDAP_ATTRIBUTE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.UUID_LDAP_ATTRIBUTE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.USER_OBJECT_CLASSES)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.CONNECTION_URL)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.USERS_DN)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.RELATIVE_CREATE_DN)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.AUTH_TYPE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("simple")
                .add()
                .property().name(LDAPConstants.START_TLS)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .add()
                .property().name(LDAPConstants.BIND_DN)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.BIND_CREDENTIAL)
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()
                .property().name(LDAPConstants.CUSTOM_USER_SEARCH_FILTER)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.SEARCH_SCOPE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("1")
                .add()
                .property().name(LDAPConstants.VALIDATE_PASSWORD_POLICY)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(LDAPConstants.TRUST_EMAIL)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(LDAPConstants.USE_TRUSTSTORE_SPI)
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("always")
                .add()
                .property().name(LDAPConstants.CONNECTION_POOLING)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property().name(LDAPConstants.CONNECTION_TIMEOUT)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.READ_TIMEOUT)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(LDAPConstants.PAGINATION)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property().name(LDAPConfig.SYNC_ATTRIBUTE_PRIORITIES)
                .label("Attribute Conflict Priorities")
                .helpText("Per-field conflict policy for user synchronization, for example 'email=DIRECTORY,phone=LOCAL'. "
                        + "LOCAL keeps a local value when both sides changed; DIRECTORY applies the LDAP value.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("")
                .add()
                .property().name(LDAPConfig.SYNC_DELETION_MODE)
                .label("Directory Deletion Mode")
                .helpText("LEGACY keeps the existing behavior. DISABLE disables users that disappeared from a completed "
                        + "full directory sync without deleting local data. Local users not linked to this provider are never touched.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(List.of(LDAPConfig.SYNC_DELETION_LEGACY, LDAPConfig.SYNC_DELETION_DISABLE))
                .defaultValue(LDAPConfig.SYNC_DELETION_LEGACY)
                .add()
                .property().name(LDAPConfig.SYNC_GROUP_OWNERSHIP)
                .label("Track Directory-Managed Groups")
                .helpText("Marks groups imported from LDAP and keeps manually-created groups and their memberships intact during group synchronization.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property().name(LDAPConstants.REFERRAL)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(KerberosConstants.SERVER_PRINCIPAL)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(KerberosConstants.KEYTAB)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(KerberosConstants.KERBEROS_REALM)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(KerberosConstants.ALLOWED_KERBEROS_REALMS)
                .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
                .add()
                .property().name(KerberosConstants.KERBEROS_PRINCIPAL_ATTRIBUTE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(KerberosConstants.DEBUG)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(KerberosConstants.USE_KERBEROS_FOR_PASSWORD_AUTHENTICATION)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(LDAPConstants.CONNECTION_TRACE)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property().name(LDAPConstants.ENABLE_LDAP_PASSWORD_POLICY)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .build();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public LDAPStorageProvider create(KeycloakSession session, ComponentModel model) {
        Map<ComponentModel, LDAPConfigDecorator> configDecorators = getLDAPConfigDecorators(session, model);

        LDAPIdentityStore ldapIdentityStore = this.ldapStoreRegistry.getLdapStore(session, model, configDecorators, ldapRequestTimer);
        return new LDAPStorageProvider(this, session, model, ldapIdentityStore);
    }


    // Check if it's some performance overhead to create this map in every request. But probably not...
    protected Map<ComponentModel, LDAPConfigDecorator> getLDAPConfigDecorators(KeycloakSession session, ComponentModel ldapModel) {
        RealmModel realm = session.realms().getRealm(ldapModel.getParentId());
        return realm.getComponentsStream(ldapModel.getId(), LDAPStorageMapper.class.getName())
                .filter(mapperModel -> session.getKeycloakSessionFactory()
                        .getProviderFactory(LDAPStorageMapper.class, mapperModel.getProviderId()) instanceof LDAPConfigDecorator)
                .collect(Collectors.toMap(Function.identity(), mapperModel ->
                        (LDAPConfigDecorator) session.getKeycloakSessionFactory()
                                .getProviderFactory(LDAPStorageMapper.class, mapperModel.getProviderId())));
    }


    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        LDAPConfig cfg = new LDAPConfig(config.getConfig());
        UserStorageProviderModel userStorageModel = new UserStorageProviderModel(config);
        String customFilter = cfg.getCustomUserSearchFilter();
        LDAPUtils.validateCustomLdapFilter(customFilter);

        String connectionTimeout = cfg.getConnectionTimeout();
        if (connectionTimeout != null && !connectionTimeout.isEmpty()) {
            try {
                Long.parseLong(connectionTimeout);
            } catch (NumberFormatException nfe) {
                throw new ComponentValidationException("ldapErrorConnectionTimeoutNotNumber");
            }
        }

        String readTimeout = cfg.getReadTimeout();
        if (readTimeout != null && !readTimeout.isEmpty()) {
            try {
                Long.parseLong(readTimeout);
            } catch (NumberFormatException nfe) {
                throw new ComponentValidationException("ldapErrorReadTimeoutNotNumber");
            }
        }

        String connectionUrl = cfg.getConnectionUrl();
        if (connectionUrl != null) {
            if (connectionUrl.contains(",")) {
                throw new ComponentValidationException("ldapErrorConnectionUrlContainsComma");
            }
            for (String url : LDAPConstants.toLdapUrls(connectionUrl)) {
                try {
                    URI uri = URI.create(url);
                    String scheme = uri.getScheme();
                    if (scheme == null || !(scheme.equalsIgnoreCase("ldap") || scheme.equalsIgnoreCase("ldaps"))) {
                        throw new ComponentValidationException("ldapErrorInvalidConnectionUrlScheme");
                    }
                } catch (IllegalArgumentException e) {
                    throw new ComponentValidationException("ldapErrorInvalidConnectionUrl");
                }
            }
        }

        // This parses the configuration directly as cfg.getConnectionPooling() will take into account the current StartTLS setting
        if(cfg.isStartTls() && Boolean.parseBoolean(config.getConfig().getFirst(LDAPConstants.CONNECTION_POOLING))) {
            throw new ComponentValidationException("ldapErrorCantEnableStartTlsAndConnectionPooling");
        }

        // editMode is mandatory
        if (config.get(LDAPConstants.EDIT_MODE) == null) {
            throw new ComponentValidationException("ldapErrorEditModeMandatory");
        }

        // validatePasswordPolicy applicable only for WRITABLE mode
        if (cfg.getEditMode() != UserStorageProvider.EditMode.WRITABLE) {
            if (cfg.isValidatePasswordPolicy()) {
                throw new ComponentValidationException("ldapErrorValidatePasswordPolicyAvailableForWritableOnly");
            }
        }

        if (!userStorageModel.isImportEnabled() && cfg.getEditMode() == UserStorageProvider.EditMode.UNSYNCED) {
            throw new ComponentValidationException("ldapErrorCantEnableUnsyncedAndImportOff");
        }

        if (config.getId() == null) {
            // the ldap component is being created, use short id for ldap components
            config.setId(KeycloakModelUtils.generateShortId());
        } else {
            // Updating an existing LDAP provider - check if the connection URL changed while
            // the bind credential was not re-entered (auto-preserved via SECRET_VALUE placeholder or omitted).
            // This prevents credentials from being silently sent to a different server.
            validateBindCredentialOnUrlChange(session, realm, config, cfg);
        }
    }

    @SuppressWarnings("unchecked")
    private void validateBindCredentialOnUrlChange(KeycloakSession session, RealmModel realm,
                                                   ComponentModel config, LDAPConfig cfg) {
        ComponentModel oldComponent = realm.getComponent(config.getId());
        if (oldComponent == null) {
            return;
        }

        // Skip only when both sides use anonymous auth AND the old component has no stored credential.
        // AUTH_TYPE_NONE alone is not enough: a component can carry a credential in its config even
        // when auth type is none, which could be silently reused after a URL change + auth-type switch.
        LDAPConfig oldCfg = new LDAPConfig(oldComponent.getConfig());
        boolean bothAnonymous = LDAPConstants.AUTH_TYPE_NONE.equals(cfg.getAuthType())
                && LDAPConstants.AUTH_TYPE_NONE.equals(oldCfg.getAuthType());
        if (bothAnonymous && oldComponent.getConfig().getFirst(LDAPConstants.BIND_CREDENTIAL) == null) {
            return;
        }

        Set<String> secretPlaceholderFields = session.getAttribute(
                ComponentResource.SECRET_PLACEHOLDER_FIELDS_ATTR, Set.class);
        if (secretPlaceholderFields == null || !secretPlaceholderFields.contains(LDAPConstants.BIND_CREDENTIAL)) {
            // Bind credential was explicitly provided (not a SECRET_VALUE placeholder), no risk.
            return;
        }

        String oldUrl = oldComponent.getConfig().getFirst(LDAPConstants.CONNECTION_URL);
        String newUrl = config.getConfig().getFirst(LDAPConstants.CONNECTION_URL);
        if (!LDAPUtil.checkLdapConnectionUrlsMatch(oldUrl, newUrl)) {
            throw new ComponentValidationException("ldapErrorCredentialReentryRequiredOnUrlChange");
        }

        String oldBindDn = oldComponent.getConfig().getFirst(LDAPConstants.BIND_DN);
        String newBindDn = config.getConfig().getFirst(LDAPConstants.BIND_DN);
        if (!Objects.equals(oldBindDn == null ? null : oldBindDn.toLowerCase(Locale.ROOT),
                            newBindDn == null ? null : newBindDn.toLowerCase(Locale.ROOT))) {
            throw new ComponentValidationException("ldapErrorCredentialReentryRequiredOnUrlChange");
        }
    }

    @Override
    public void init(Config.Scope config) {
        if (config.getBoolean(SECURE_REFERRAL, SECURE_REFERRAL_DEFAULT)) {
            setObjectFactoryBuilder();
        } else {
            logger.warnf("Insecure LDAP referrals are enabled. The option 'secure-referral' is deprecated and it will be removed in future releases.");
        }

        // set connection pooling for plain and tls protocols by default
        if (System.getProperty(LDAP_CONNECTION_POOL_PROTOCOL) == null) {
            System.setProperty(LDAP_CONNECTION_POOL_PROTOCOL, "plain ssl");
        }

        this.disableKerberosAuthenticationRoundTrip = config.getBoolean("disableKerberosAuthenticationRoundTrip", Boolean.FALSE);
        this.ldapStoreRegistry = new LDAPIdentityStoreRegistry();
        boolean ldapMetricsFeature = Profile.isFeatureEnabled(Profile.Feature.LDAP_METRICS);
        boolean metricsEnabledConfig = config.getBoolean(METRICS_ENABLED, true);
        boolean globalMetricsEnabled = config.root().getBoolean(MetricsOptions.METRICS_ENABLED.getKey(), false);
        boolean metricsEnabled = ldapMetricsFeature && metricsEnabledConfig && globalMetricsEnabled;

        if (metricsEnabled) {
            this.ldapRequestTimer = Timer.builder("keycloak.ldap.requests")
                    .description("Time taken for LDAP requests")
                    .withRegistry(Metrics.globalRegistry);
        }

    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {

        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

        builder.property()
                .name(SECURE_REFERRAL)
                .type("boolean")
                .helpText("Allow only secure LDAP referrals (deprecated)")
                .defaultValue(SECURE_REFERRAL_DEFAULT)
                .add()

                .property()
                .name("disableKerberosAuthenticationRoundTrip")
                .type("boolean")
                .helpText("Boolean to disable the local Kerberos service-ticket round trip in username/password authentication (deprecated).")
                .defaultValue("false")
                .add();

        return builder.build();

    }

    @Override
    public void close() {
        this.ldapStoreRegistry = null;
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    // Best effort to create appropriate mappers according to our LDAP config
    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        LDAPConfig ldapConfig = new LDAPConfig(model.getConfig());

        boolean activeDirectory = ldapConfig.isActiveDirectory();
        UserStorageProvider.EditMode editMode = ldapConfig.getEditMode();
        String readOnly = String.valueOf(editMode == UserStorageProvider.EditMode.READ_ONLY || editMode == UserStorageProvider.EditMode.UNSYNCED);
        String usernameLdapAttribute = ldapConfig.getUsernameLdapAttribute();
        boolean syncRegistrations = Boolean.valueOf(model.getConfig().getFirst(LDAPConstants.SYNC_REGISTRATIONS));

        String alwaysReadValueFromLDAP = String.valueOf(editMode== UserStorageProvider.EditMode.READ_ONLY || editMode== UserStorageProvider.EditMode.WRITABLE);

        ComponentModel mapperModel;
        mapperModel = KeycloakModelUtils.createComponentModel("username", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.USERNAME,
                UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, usernameLdapAttribute,
                UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, "false",
                UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
        realm.addComponentModel(mapperModel);

        // CN is typically used as RDN for Active Directory deployments
        if (ldapConfig.getRdnLdapAttribute().equalsIgnoreCase(LDAPConstants.CN)) {

            if (usernameLdapAttribute.equalsIgnoreCase(LDAPConstants.CN)) {

                // For AD deployments with "cn" as username, we will map "givenName" to first name
                mapperModel = KeycloakModelUtils.createComponentModel("first name", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                        UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.FIRST_NAME,
                        UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.GIVENNAME,
                        UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                        UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                        UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
                realm.addComponentModel(mapperModel);

            } else {
                if (editMode == UserStorageProvider.EditMode.WRITABLE) {

                    // For AD deployments with "sAMAccountName" as username and writable, we need to map "cn" as username as well (this is needed so we can register new users from KC into LDAP) and we will map "givenName" to first name.
                    mapperModel = KeycloakModelUtils.createComponentModel("first name", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                            UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.FIRST_NAME,
                            UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.GIVENNAME,
                            UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                            UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                            UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
                    realm.addComponentModel(mapperModel);

                    mapperModel = KeycloakModelUtils.createComponentModel("username-cn", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                            UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.USERNAME,
                            UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.CN,
                            UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                            UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, "false",
                            UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
                    realm.addComponentModel(mapperModel);
                } else {

                    // For read-only LDAP, we map "cn" as full name
                    mapperModel = KeycloakModelUtils.createComponentModel("full name", model.getId(), FullNameLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                            FullNameLDAPStorageMapper.LDAP_FULL_NAME_ATTRIBUTE, LDAPConstants.CN,
                            FullNameLDAPStorageMapper.READ_ONLY, readOnly,
                            FullNameLDAPStorageMapper.WRITE_ONLY, "false");
                    realm.addComponentModel(mapperModel);
                }
            }
        } else {
            mapperModel = KeycloakModelUtils.createComponentModel("first name", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                    UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.FIRST_NAME,
                    UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.CN,
                    UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                    UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                    UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
            realm.addComponentModel(mapperModel);
        }

        mapperModel = KeycloakModelUtils.createComponentModel("last name", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.LAST_NAME,
                UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.SN,
                UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
        realm.addComponentModel(mapperModel);

        mapperModel = KeycloakModelUtils.createComponentModel("email", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.EMAIL,
                UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.EMAIL,
                UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, "false",
                UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "false");
        realm.addComponentModel(mapperModel);

        String createTimestampLdapAttrName = activeDirectory ? "whenCreated" : LDAPConstants.CREATE_TIMESTAMP;
        String modifyTimestampLdapAttrName = activeDirectory ? "whenChanged" : LDAPConstants.MODIFY_TIMESTAMP;

        // map createTimeStamp as read-only
        mapperModel = KeycloakModelUtils.createComponentModel("creation date", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, LDAPConstants.CREATE_TIMESTAMP,
                UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, createTimestampLdapAttrName,
                UserAttributeLDAPStorageMapper.READ_ONLY, "true",
                UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "false");
        realm.addComponentModel(mapperModel);

        // map modifyTimeStamp as read-only
        mapperModel = KeycloakModelUtils.createComponentModel("modify date", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, LDAPConstants.MODIFY_TIMESTAMP,
                UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, modifyTimestampLdapAttrName,
                UserAttributeLDAPStorageMapper.READ_ONLY, "true",
                UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "false");
        realm.addComponentModel(mapperModel);

        // MSAD specific mapper for account state propagation
        if (activeDirectory) {
            mapperModel = KeycloakModelUtils.createComponentModel("MSAD account controls", model.getId(), MSADUserAccountControlStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                    MSADUserAccountControlStorageMapper.ALWAYS_READ_ENABLED_VALUE_FROM_LDAP, alwaysReadValueFromLDAP);
            realm.addComponentModel(mapperModel);
        }

        LDAPProviderKerberosConfig kerberosConfig = new LDAPProviderKerberosConfig(model);
        if (kerberosConfig.isAllowKerberosAuthentication()) {
            CredentialHelper.setOrReplaceAuthenticationRequirement(session, realm, CredentialRepresentation.KERBEROS,
                    AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED);
        }

        if (kerberosConfig.getKerberosPrincipalAttribute() == null) {
            String defaultKerberosUserPrincipalAttr = LDAPUtils.getDefaultKerberosUserPrincipalAttribute(ldapConfig.getVendor());
            model.getConfig().putSingle(KerberosConstants.KERBEROS_PRINCIPAL_ATTRIBUTE, defaultKerberosUserPrincipalAttr);
            realm.updateComponent(model);
        }

        if (kerberosConfig.getKerberosPrincipalAttribute() != null) {
            mapperModel = KeycloakModelUtils.createComponentModel("Kerberos principal attribute mapper", model.getId(), KerberosPrincipalAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName());
            realm.addComponentModel(mapperModel);
        }

        // In case that "Sync Registration" is ON and the LDAP v3 Password-modify extension is ON, we will create hardcoded mapper to create
        // random "userPassword" every time when creating user. Otherwise users won't be able to register and login
        if (!activeDirectory && syncRegistrations && ldapConfig.useExtendedPasswordModifyOp()) {
            mapperModel = KeycloakModelUtils.createComponentModel("random initial password", model.getId(), HardcodedLDAPAttributeMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                    HardcodedLDAPAttributeMapper.LDAP_ATTRIBUTE_NAME, LDAPConstants.USER_PASSWORD_ATTRIBUTE,
                    HardcodedLDAPAttributeMapper.LDAP_ATTRIBUTE_VALUE, HardcodedLDAPAttributeMapper.RANDOM_ATTRIBUTE_VALUE);
            realm.addComponentModel(mapperModel);
        }
    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        boolean allowKerberosCfgOld = Boolean.valueOf(oldModel.getConfig().getFirst(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION));
        boolean allowKerberosCfgNew = Boolean.valueOf(newModel.getConfig().getFirst(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION));
        if (!allowKerberosCfgOld && allowKerberosCfgNew) {
            CredentialHelper.setOrReplaceAuthenticationRequirement(session, realm, CredentialRepresentation.KERBEROS,
                    AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED);
        } else if(allowKerberosCfgOld && !allowKerberosCfgNew) {
            CredentialHelper.setOrReplaceAuthenticationRequirement(session, realm, CredentialRepresentation.KERBEROS,
                    AuthenticationExecutionModel.Requirement.DISABLED, AuthenticationExecutionModel.Requirement.ALTERNATIVE);
        } // else: keep current settings

        LDAPConfig oldConfig = new LDAPConfig(oldModel.getConfig());
        LDAPConfig newConfig = new LDAPConfig(newModel.getConfig());
        if (!oldConfig.getUsernameLdapAttribute().equals(newConfig.getUsernameLdapAttribute())) {
            // propagate username LDAP attribute change to the username mapper.
            ComponentModel usernameMapperModel = realm.getComponentsStream(oldModel.getId(), LDAPStorageMapper.class.getName())
                    .filter(mapper -> "username".equals(mapper.getName()))
                    .findFirst().orElse(null);
            if (usernameMapperModel != null) {
                usernameMapperModel.getConfig().putSingle(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, newConfig.getUsernameLdapAttribute());
                realm.updateComponent(usernameMapperModel);
            }
        }
    }

    @Override
    public void preRemove(KeycloakSession session, RealmModel realm, ComponentModel model) {
        String allowKerberosCfg = model.getConfig().getFirst(KerberosConstants.ALLOW_KERBEROS_AUTHENTICATION);
        if (Boolean.valueOf(allowKerberosCfg)) {
            CredentialHelper.setOrReplaceAuthenticationRequirement(session, realm, CredentialRepresentation.KERBEROS,
                    AuthenticationExecutionModel.Requirement.DISABLED, null);
        }
    }

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        logger.infof("Sync all users from LDAP to local store: realm: %s, federation provider: %s", realmId, model.getName());
        SynchronizationResult syncResult = syncMode(SyncMode.FULL, null, sessionFactory, realmId, model);
        logger.infof("Sync all users finished: %s", syncResult.getStatus());
        return syncResult;
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        logger.infof("Sync changed users from LDAP to local store: realm: %s, federation provider: %s, last sync time: " + lastSync, realmId, model.getName());
        SynchronizationResult result = syncMode(SyncMode.CHANGED, lastSync, sessionFactory, realmId, model);
        logger.infof("Sync changed users finished: %s", result.getStatus());
        return result;
    }

    private SynchronizationResult syncMode(SyncMode mode, Date lastSync, KeycloakSessionFactory sessionFactory,
                                           String realmId, ComponentModel model) {
        SyncState state = prepareSyncState(sessionFactory, realmId, model, mode);
        SynchronizationResult syncResult = new SynchronizationResult();
        syncResult.setResumed(state.resumed);
        updateProgress(syncResult, state, "MAPPERS");
        persistSyncState(sessionFactory, realmId, model.getId(), mode, current -> {
            current.setSyncStatus(mode, SyncStatus.RUNNING);
            current.setSyncPhase(mode, "MAPPERS");
            current.setSyncRetryable(mode, false);
            current.setSyncUpdatedAt(mode, org.keycloak.common.util.Time.currentTimeMillis());
        });

        syncResult.add(syncMappers(sessionFactory, realmId, model));
        if (syncResult.isRetryable()) {
            finalizeSyncState(sessionFactory, realmId, model.getId(), mode, state, syncResult);
            return syncResult;
        }

        try (LDAPQuery userQuery = createQuery(sessionFactory, realmId, model)) {
            if (lastSync != null) {
                LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();
                Condition createCondition = conditionsBuilder.greaterThanOrEqualTo(LDAPConstants.CREATE_TIMESTAMP, lastSync);
                Condition modifyCondition = conditionsBuilder.greaterThanOrEqualTo(LDAPConstants.MODIFY_TIMESTAMP, lastSync);
                userQuery.addWhereCondition(conditionsBuilder.orCondition(createCondition, modifyCondition));
            }
            syncResult.add(syncImpl(sessionFactory, userQuery, realmId, model, mode, state));
        } catch (Throwable t) {
            addFailure(syncResult, t, "fetching LDAP users");
        }

        if (mode == SyncMode.FULL && !syncResult.isRetryable() && syncResult.getNonRetryableFailures() == 0) {
            try {
                syncResult.add(disableDeletedUsers(sessionFactory, realmId, model, state.runId));
            } catch (Throwable t) {
                addFailure(syncResult, t, "propagating directory deletions");
            }
        }

        finalizeSyncState(sessionFactory, realmId, model.getId(), mode, state, syncResult);
        return syncResult;
    }

    protected SynchronizationResult syncMappers(KeycloakSessionFactory sessionFactory, final String realmId, final ComponentModel model) {
        SynchronizationResult result = new SynchronizationResult();
        List<ComponentModel> mapperModels;
        try {
            mapperModels = KeycloakModelUtils.runJobInTransactionWithResult(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                session.getContext().setRealm(realm);
                return realm.getComponentsStream(model.getId(), LDAPStorageMapper.class.getName()).toList();
            });
        } catch (Throwable t) {
            addFailure(result, t, "loading LDAP mappers");
            return result;
        }

        for (ComponentModel mapperModel : mapperModels) {
            try {
                SynchronizationResult mapperResult = KeycloakModelUtils.runJobInTransactionWithResult(sessionFactory, session -> {
                    RealmModel realm = session.realms().getRealm(realmId);
                    session.getContext().setRealm(realm);
                    session.getProvider(UserStorageProvider.class, model);
                    return session.getProvider(LDAPStorageMapper.class, mapperModel)
                            .syncDataFromFederationProviderToKeycloak(realm);
                });
                result.add(mapperResult);
                if (mapperResult.getAdded() > 0 || mapperResult.getUpdated() > 0 || mapperResult.getRemoved() > 0
                        || mapperResult.getFailed() > 0 || mapperResult.getConflicts() > 0) {
                    logger.infof("Sync of federation mapper '%s' finished. Status: %s", mapperModel.getName(), mapperResult.getStatus());
                }
            } catch (Throwable t) {
                addFailure(result, t, "syncing federation mapper " + mapperModel.getName());
            }
        }
        return result;
    }

    protected SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, LDAPQuery userQuery,
                                             final String realmId, final ComponentModel fedModel,
                                             SyncMode mode, SyncState state) {
        final SynchronizationResult syncResult = new SynchronizationResult();
        LDAPConfig ldapConfig = new LDAPConfig(fedModel.getConfig());
        updateProgress(syncResult, state, "USERS");

        if (mode == SyncMode.FULL && state.total < 0) {
            state.total = countUsers(sessionFactory, realmId, fedModel);
        }
        if (state.total >= 0) {
            syncResult.setTotal(state.total);
            syncResult.setRemaining(remaining(state));
        }

        boolean pagination = ldapConfig.isPagination();
        String seenRunId = mode == SyncMode.FULL && LDAPConfig.SYNC_DELETION_DISABLE.equals(ldapConfig.getSyncDeletionMode())
                ? state.runId : null;
        if (pagination) {
            int pageSize = ldapConfig.getBatchSizeForSync();
            if (state.resumed && state.cursor != null) {
                userQuery.setInitialPaginationCookie(decodeCursor(state.cursor));
            }

            boolean nextPage = true;
            while (nextPage) {
                final List<LDAPObject> users;
                try {
                    userQuery.setLimit(pageSize);
                    users = userQuery.getResultList();
                    nextPage = userQuery.getPaginationContext().hasNextPage();
                } catch (Throwable t) {
                    addFailure(syncResult, t, "fetching an LDAP users page");
                    updateProgress(syncResult, state, "RETRYING");
                    persistSyncState(sessionFactory, realmId, fedModel.getId(), mode, current -> {
                        current.setSyncStatus(mode, SyncStatus.FAILED);
                        current.setSyncPhase(mode, "RETRYING");
                        current.setSyncRetryable(mode, syncResult.isRetryable());
                        current.setSyncProcessed(mode, state.processed);
                        current.setSyncCursor(mode, state.cursor);
                        current.setSyncTotal(mode, state.total);
                        current.setSyncRemaining(mode, remaining(state));
                        current.setSyncUpdatedAt(mode, org.keycloak.common.util.Time.currentTimeMillis());
                    });
                    return syncResult;
                }

                SynchronizationResult currentPageSync = importLdapUsers(sessionFactory, realmId, fedModel, users, seenRunId);
                syncResult.add(currentPageSync);
                if (currentPageSync.isRetryable()) {
                    updateProgress(syncResult, state, "RETRYING");
                    persistSyncState(sessionFactory, realmId, fedModel.getId(), mode, current -> {
                        current.setSyncStatus(mode, SyncStatus.FAILED);
                        current.setSyncPhase(mode, "RETRYING");
                        current.setSyncRetryable(mode, true);
                        current.setSyncProcessed(mode, state.processed);
                        current.setSyncCursor(mode, state.cursor);
                        current.setSyncTotal(mode, state.total);
                        current.setSyncRemaining(mode, remaining(state));
                        current.setSyncUpdatedAt(mode, org.keycloak.common.util.Time.currentTimeMillis());
                    });
                    return syncResult;
                }

                state.processed += users.size();
                state.cursor = nextPage ? encodeCursor(userQuery.getPaginationContext().getCookie()) : null;
                updateProgress(syncResult, state, "USERS");
                persistSyncState(sessionFactory, realmId, fedModel.getId(), mode, current -> {
                    current.setSyncStatus(mode, SyncStatus.RUNNING);
                    current.setSyncPhase(mode, "USERS");
                    current.setSyncRetryable(mode, false);
                    current.setSyncProcessed(mode, state.processed);
                    current.setSyncCursor(mode, state.cursor);
                    current.setSyncTotal(mode, state.total);
                    current.setSyncRemaining(mode, remaining(state));
                    current.setSyncUpdatedAt(mode, org.keycloak.common.util.Time.currentTimeMillis());
                });
            }
        } else {
            // LDAP pagination not available. Do everything in single transaction
            try {
                final List<LDAPObject> users = userQuery.getResultList();
                SynchronizationResult currentSync = importLdapUsers(sessionFactory, realmId, fedModel, users, seenRunId);
                syncResult.add(currentSync);
                if (!currentSync.isRetryable()) {
                    state.processed += users.size();
                    state.total = users.size();
                }
            } catch (Throwable t) {
                addFailure(syncResult, t, "fetching LDAP users");
            }
        }

        updateProgress(syncResult, state, "USERS");
        return syncResult;
    }

    protected SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, LDAPQuery userQuery,
                                             String realmId, ComponentModel fedModel) {
        SyncState state = new SyncState();
        state.runId = UUID.randomUUID().toString();
        return syncImpl(sessionFactory, userQuery, realmId, fedModel, SyncMode.FULL, state);
    }

    private void finalizeSyncState(KeycloakSessionFactory sessionFactory, String realmId, String modelId,
                                   SyncMode mode, SyncState state, SynchronizationResult result) {
        boolean retryable = result.isRetryable();
        if (!retryable) {
            state.cursor = null;
            if (state.total < 0) {
                state.total = state.processed;
            }
            state.remaining = 0;
        }
        updateProgress(result, state, retryable ? "RETRYING" : "COMPLETE");
        persistSyncState(sessionFactory, realmId, modelId, mode, current -> {
            current.setSyncStatus(mode, retryable ? SyncStatus.FAILED : SyncStatus.COMPLETE);
            current.setSyncPhase(mode, retryable ? "RETRYING" : "COMPLETE");
            current.setSyncRetryable(mode, retryable);
            current.setSyncProcessed(mode, state.processed);
            current.setSyncCursor(mode, state.cursor);
            current.setSyncTotal(mode, state.total);
            current.setSyncRemaining(mode, retryable ? remaining(state) : 0);
            current.setSyncUpdatedAt(mode, org.keycloak.common.util.Time.currentTimeMillis());
        });
    }

    private SyncState prepareSyncState(KeycloakSessionFactory sessionFactory, String realmId, ComponentModel model, SyncMode mode) {
        SyncState state = new SyncState();
        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) {
                throw new ModelException("Realm " + realmId + " not found while preparing user synchronization");
            }
            session.getContext().setRealm(realm);
            ComponentModel component = realm.getComponent(model.getId());
            if (component == null) {
                throw new ModelException("User storage provider " + model.getId() + " not found in realm " + realmId);
            }
            UserStorageProviderModel current = new UserStorageProviderModel(component);
            SyncStatus status = current.getSyncStatus(mode);
            String cursor = current.getSyncCursor(mode);
            state.resumed = (status == SyncStatus.RUNNING || status == SyncStatus.FAILED) && cursor != null;
            state.cursor = state.resumed ? cursor : null;
            state.processed = state.resumed ? current.getSyncProcessed(mode) : 0;
            state.total = state.resumed ? current.getSyncTotal(mode) : -1;
            state.runId = state.resumed ? current.getSyncRunId(mode) : null;
            if (state.runId == null) {
                state.runId = UUID.randomUUID().toString();
            }
            state.remaining = remaining(state);

            current.setSyncStatus(mode, SyncStatus.RUNNING);
            current.setSyncPhase(mode, "MAPPERS");
            current.setSyncProcessed(mode, state.processed);
            current.setSyncCursor(mode, state.cursor);
            current.setSyncTotal(mode, state.total);
            current.setSyncRemaining(mode, state.remaining);
            current.setSyncRunId(mode, state.runId);
            current.setSyncRetryable(mode, false);
            current.setSyncUpdatedAt(mode, org.keycloak.common.util.Time.currentTimeMillis());
            realm.updateComponent(current);
        });
        return state;
    }

    private void persistSyncState(KeycloakSessionFactory sessionFactory, String realmId, String modelId,
                                  SyncMode mode, Consumer<UserStorageProviderModel> update) {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) {
                return;
            }
            session.getContext().setRealm(realm);
            ComponentModel component = realm.getComponent(modelId);
            if (component == null) {
                return;
            }
            UserStorageProviderModel current = new UserStorageProviderModel(component);
            update.accept(current);
            realm.updateComponent(current);
        });
    }

    private void updateProgress(SynchronizationResult result, SyncState state, String phase) {
        state.remaining = remaining(state);
        result.setProcessed(state.processed);
        result.setTotal(state.total);
        result.setRemaining(state.remaining);
        result.setCursor(state.cursor);
        result.setPhase(phase);
    }

    private static int remaining(SyncState state) {
        return state.total < 0 ? -1 : Math.max(state.total - state.processed, 0);
    }

    private int countUsers(KeycloakSessionFactory sessionFactory, String realmId, ComponentModel model) {
        try (LDAPQuery countQuery = createQuery(sessionFactory, realmId, model)) {
            return countQuery.getResultCount();
        } catch (Throwable t) {
            logger.warnf(t, "Unable to determine total number of LDAP users for synchronization progress");
            return -1;
        }
    }

    private String encodeCursor(byte[] cursor) {
        return cursor == null ? null : Base64.getUrlEncoder().withoutPadding().encodeToString(cursor);
    }

    private byte[] decodeCursor(String cursor) {
        return cursor == null ? null : Base64.getUrlDecoder().decode(cursor);
    }

    /**
     *  !! This function must be called from try-with-resources block, otherwise Vault secrets may be leaked !!
     * @param sessionFactory
     * @param realmId
     * @param model
     * @return
     */
    private LDAPQuery createQuery(KeycloakSessionFactory sessionFactory, final String realmId, final ComponentModel model) {
        class QueryHolder {
            LDAPQuery query;
        }

        final QueryHolder queryHolder = new QueryHolder();
        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

            @Override
            public void run(KeycloakSession session) {
                session.getContext().setRealm(session.realms().getRealm(realmId));

                LDAPStorageProvider ldapFedProvider = (LDAPStorageProvider)session.getProvider(UserStorageProvider.class, model);
                RealmModel realm = session.realms().getRealm(realmId);
                queryHolder.query = LDAPUtils.createQueryForUserSearch(ldapFedProvider, realm);
            }

        });
        return queryHolder.query;
    }

    protected SynchronizationResult importLdapUsers(KeycloakSessionFactory sessionFactory, final String realmId,
                                                    final ComponentModel fedModel, List<LDAPObject> ldapUsers,
                                                    String runId) {
        final SynchronizationResult syncResult = new SynchronizationResult();

        for (final LDAPObject ldapUser : ldapUsers) {
            class BooleanHolder {
                private boolean value = true;
            }
            final BooleanHolder exists = new BooleanHolder();
            final List<SyncConflict> userConflicts = new ArrayList<>();

            try {
                // Process each user in its own transaction to avoid aborting the whole batch.
                KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                    LDAPStorageProvider ldapFedProvider = (LDAPStorageProvider) session.getProvider(UserStorageProvider.class, fedModel);
                    RealmModel currentRealm = session.realms().getRealm(realmId);
                    session.getContext().setRealm(currentRealm);

                    String username = LDAPUtils.getUsername(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
                    exists.value = true;
                    LDAPUtils.checkUuid(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
                    UserModel currentUserLocal = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(currentRealm, username);
                    Optional<UserModel> userModelOptional = UserStoragePrivateUtil.userLocalStorage(session)
                            .searchForUserByUserAttributeStream(currentRealm, LDAPConstants.LDAP_ID, ldapUser.getUuid())
                            .findFirst();
                    if (userModelOptional.isEmpty() && currentUserLocal == null) {
                        exists.value = false;
                        UserModel imported = ldapFedProvider.importUserFromLDAP(session, currentRealm, ldapUser);
                        if (runId != null) {
                            imported.setSingleAttribute(UserSyncMetadata.SEEN_RUN_ATTRIBUTE, runId);
                        }
                        syncResult.increaseAdded();
                    } else {
                        UserModel currentUser = userModelOptional.isPresent() ? userModelOptional.get() : currentUserLocal;
                        if (fedModel.getId().equals(currentUser.getFederationLink())
                                && ldapUser.getUuid().equals(currentUser.getFirstAttribute(LDAPConstants.LDAP_ID))) {
                            if (runId != null) {
                                currentUser.setSingleAttribute(UserSyncMetadata.SEEN_RUN_ATTRIBUTE, runId);
                            }
                            if (currentUser.getFirstAttribute(UserSyncMetadata.DELETED_AT_ATTRIBUTE) != null) {
                                currentUser.setEnabled(true);
                                currentUser.removeAttribute(UserSyncMetadata.DELETED_AT_ATTRIBUTE);
                                currentUser.removeAttribute(UserSyncMetadata.DELETED_BY_ATTRIBUTE);
                            }

                            LDAPMappersComparator ldapMappersComparator = new LDAPMappersComparator(ldapFedProvider.getLdapIdentityStore().getConfig());
                            currentRealm.getComponentsStream(fedModel.getId(), LDAPStorageMapper.class.getName())
                                    .sorted(ldapMappersComparator.sortDesc())
                                    .forEachOrdered(mapperModel -> {
                                        LDAPStorageMapper ldapMapper = ldapFedProvider.getMapperManager().getMapper(mapperModel);
                                        ldapMapper.resetImportConflicts();
                                        ldapMapper.onImportUserFromLDAP(ldapUser, currentUser, currentRealm, false);
                                        userConflicts.addAll(ldapMapper.getImportConflicts());
                                    });

                            UserCache userCache = UserStorageUtil.userCache(session);
                            if (userCache != null) {
                                userCache.evict(currentRealm, currentUser);
                            }
                            logger.debugf("Updated user from LDAP: %s", currentUser.getUsername());
                            syncResult.increaseUpdated();
                        } else {
                            logger.warnf("User with ID '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'", ldapUser.getUuid(), fedModel.getName());
                            syncResult.increaseNonRetryableFailure();
                            syncResult.increaseSkipped();
                        }
                    }
                });

                for (SyncConflict conflict : userConflicts) {
                    syncResult.addConflict(conflict);
                }
            } catch (Throwable t) {
                addFailure(syncResult, t, "importing LDAP user " + ldapUser.getDn());
                cleanupFailedNewUser(sessionFactory, realmId, fedModel, ldapUser, exists.value);
                if (syncResult.isRetryable()) {
                    break;
                }
            }
        }

        return syncResult;
    }

    protected SynchronizationResult importLdapUsers(KeycloakSessionFactory sessionFactory, String realmId,
                                                    ComponentModel fedModel, List<LDAPObject> ldapUsers) {
        return importLdapUsers(sessionFactory, realmId, fedModel, ldapUsers, UUID.randomUUID().toString());
    }

    private void cleanupFailedNewUser(KeycloakSessionFactory sessionFactory, String realmId, ComponentModel fedModel,
                                      LDAPObject ldapUser, boolean existedBefore) {
        if (existedBefore) {
            return;
        }
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                LDAPStorageProvider ldapFedProvider = (LDAPStorageProvider) session.getProvider(UserStorageProvider.class, fedModel);
                RealmModel currentRealm = session.realms().getRealm(realmId);
                session.getContext().setRealm(currentRealm);

                String username = null;
                try {
                    username = LDAPUtils.getUsername(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
                } catch (ModelException ignore) {
                }
                if (username == null) {
                    return;
                }
                UserModel existing = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(currentRealm, username);
                if (existing != null) {
                    UserCache userCache = UserStorageUtil.userCache(session);
                    if (userCache != null) {
                        userCache.evict(currentRealm, existing);
                    }
                    UserStoragePrivateUtil.userLocalStorage(session).removeUser(currentRealm, existing);
                }
            });
        } catch (Throwable t) {
            logger.warnf(t, "Unable to clean up partially imported LDAP user %s", ldapUser.getDn());
        }
    }

    private SynchronizationResult disableDeletedUsers(KeycloakSessionFactory sessionFactory, String realmId,
                                                      ComponentModel fedModel, String runId) {
        SynchronizationResult result = new SynchronizationResult();
        LDAPConfig config = new LDAPConfig(fedModel.getConfig());
        if (!LDAPConfig.SYNC_DELETION_DISABLE.equals(config.getSyncDeletionMode())) {
            return result;
        }

        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) {
                return;
            }
            session.getContext().setRealm(realm);
            UserStoragePrivateUtil.userLocalStorage(session).searchForUserStream(realm, Collections.emptyMap())
                    .forEach(user -> {
                        if (!fedModel.getId().equals(user.getFederationLink()) || !user.isEnabled()) {
                            return;
                        }
                        if (user.getFirstAttribute(LDAPConstants.LDAP_ID) == null) {
                            return;
                        }
                        String seenRun = user.getFirstAttribute(UserSyncMetadata.SEEN_RUN_ATTRIBUTE);
                        if (seenRun == null || runId.equals(seenRun)) {
                            return;
                        }
                        long now = org.keycloak.common.util.Time.currentTimeMillis();
                        user.setEnabled(false);
                        user.setSingleAttribute(UserSyncMetadata.DELETED_AT_ATTRIBUTE, Long.toString(now));
                        user.setSingleAttribute(UserSyncMetadata.DELETED_BY_ATTRIBUTE, "directory-sync:" + fedModel.getName());
                        UserCache userCache = UserStorageUtil.userCache(session);
                        if (userCache != null) {
                            userCache.evict(realm, user);
                        }
                        result.increaseDisabled();
                        logger.warnf("Disabled user '%s' because it no longer exists in LDAP. Local data and resource references were preserved.",
                                user.getUsername());
                    });
        });
        return result;
    }

    private void addFailure(SynchronizationResult result, Throwable throwable, String operation) {
        boolean retryable = isRetryableFailure(throwable);
        if (retryable) {
            result.increaseRetryableFailure();
        } else {
            result.increaseNonRetryableFailure();
            result.increaseSkipped();
        }
        logger.warnf(throwable, "Failed %s during LDAP synchronization (%s)", operation,
                retryable ? "retryable" : "non-retryable");
    }

    private boolean isRetryableFailure(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof StorageUnavailableException
                    || current instanceof CommunicationException
                    || current instanceof NamingException
                    || current instanceof java.io.IOException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    protected static final class SyncState {
        private boolean resumed;
        private String runId;
        private String cursor;
        private int processed;
        private int total = -1;
        private int remaining = -1;
    }

    protected SPNEGOAuthenticator createSPNEGOAuthenticator(String spnegoToken, CommonKerberosConfig kerberosConfig) {
        KerberosServerSubjectAuthenticator kerberosAuth = createKerberosSubjectAuthenticator(kerberosConfig);
        return new SPNEGOAuthenticator(kerberosConfig, kerberosAuth, spnegoToken);
    }

    protected KerberosServerSubjectAuthenticator createKerberosSubjectAuthenticator(CommonKerberosConfig kerberosConfig) {
        return new KerberosServerSubjectAuthenticator(kerberosConfig);
    }

    protected KerberosUsernamePasswordAuthenticator createKerberosUsernamePasswordAuthenticator(CommonKerberosConfig kerberosConfig) {
        return new KerberosUsernamePasswordAuthenticator(kerberosConfig, disableKerberosAuthenticationRoundTrip);
    }

    private void setObjectFactoryBuilder() {
        try {
            NamingManager.setObjectFactoryBuilder(new ObjectFactoryBuilder());
        } catch (NamingException | IllegalStateException e) {
            if (e instanceof IllegalStateException && ObjectFactoryBuilder.isSet()) {
                return;
            }

            throw new RuntimeException("Failed to set the server JNDI ObjectFactoryBuilder", e);
        }
    }
}
