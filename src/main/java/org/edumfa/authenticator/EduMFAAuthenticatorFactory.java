/*
* License:  AGPLv3
* This file is part of the eduMFA Keycloak extension. eduMFA Keycloak extension is a fork of privacyIDEA keycloak provider.
* Copyright (c) 2024 eduMFA Project-Team
* Previous authors of the EduMFA java client:
*
* NetKnights GmbH
* nils.behlen@netknights.it
* lukas.matusiewicz@netknights.it
*
* This code is free software; you can redistribute it and/or
* modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
* License as published by the Free Software Foundation; either
* version 3 of the License, or any later version.
*
* This code is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU AFFERO GENERAL PUBLIC LICENSE for more details.
*
* You should have received a copy of the GNU Affero General Public
* License along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.edumfa.authenticator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class EduMFAAuthenticatorFactory implements org.keycloak.authentication.AuthenticatorFactory, org.keycloak.authentication.ConfigurableAuthenticatorFactory
{
    private static final EduMFAAuthenticator SINGLETON = new EduMFAAuthenticator();
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public String getId()
    {
        return Const.PROVIDER_ID;
    }

    @Override
    public org.keycloak.authentication.Authenticator create(KeycloakSession session)
    {
        return SINGLETON;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {AuthenticationExecutionModel.Requirement.REQUIRED,
                                                                                           AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices()
    {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed()
    {
        return false;
    }

    @Override
    public boolean isConfigurable()
    {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties()
    {
        return configProperties;
    }

    static
    {
        ProviderConfigProperty emServerUrl = new ProviderConfigProperty();
        emServerUrl.setType(ProviderConfigProperty.STRING_TYPE);
        emServerUrl.setName(Const.CONFIG_SERVER);
        emServerUrl.setLabel("eduMFA URL");
        emServerUrl.setHelpText("The URL of the eduMFAserver (complete with scheme, host and port like \"https://<edumfaserver>:port\")");
        configProperties.add(emServerUrl);

        ProviderConfigProperty emRealm = new ProviderConfigProperty();
        emRealm.setType(ProviderConfigProperty.STRING_TYPE);
        emRealm.setName(Const.CONFIG_REALM);
        emRealm.setLabel("Realm");
        emRealm.setHelpText(
                "Select the realm where your users are stored. Leave empty to use the default realm which is configured in the eduMFA server.");
        configProperties.add(emRealm);

        ProviderConfigProperty emVerifySSL = new ProviderConfigProperty();
        emVerifySSL.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emVerifySSL.setName(Const.CONFIG_VERIFY_SSL);
        emVerifySSL.setLabel("Verify SSL");
        emVerifySSL.setHelpText(
                "Do not set this to false in a productive environment. Disables the verification of the eduMFA server's certificate and hostname.");
        configProperties.add(emVerifySSL);

        List<String> prefToken = Arrays.asList("OTP", "PUSH", "WebAuthn", "U2F");
        ProviderConfigProperty emPrefToken = new ProviderConfigProperty();
        emPrefToken.setType(ProviderConfigProperty.LIST_TYPE);
        emPrefToken.setName(Const.CONFIG_PREF_TOKEN_TYPE);
        emPrefToken.setLabel("Preferred Login Token Type");
        emPrefToken.setHelpText("Select the token type for which the login interface should be shown first. " +
                                "If other token types are available for login, it will be possible to change the interface when logging in. " +
                                "If the selected token type is not available, because no token of such type was triggered, the interface will default to OTP.");
        emPrefToken.setOptions(prefToken);
        emPrefToken.setDefaultValue(prefToken.get(0));
        configProperties.add(emPrefToken);

        ProviderConfigProperty emDoTriggerChallenge = new ProviderConfigProperty();
        emDoTriggerChallenge.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emDoTriggerChallenge.setName(Const.CONFIG_TRIGGER_CHALLENGE);
        emDoTriggerChallenge.setLabel("Enable trigger challenge");
        emDoTriggerChallenge.setHelpText(
                "Choose if you want to trigger challenge-response token using the provided service account before the second step of authentication. " +
                "This setting is mutually exclusive with sending any password and will take precedence over both.");
        configProperties.add(emDoTriggerChallenge);

        ProviderConfigProperty emServiceAccount = new ProviderConfigProperty();
        emServiceAccount.setType(ProviderConfigProperty.STRING_TYPE);
        emServiceAccount.setName(Const.CONFIG_SERVICE_ACCOUNT);
        emServiceAccount.setLabel("Service account");
        emServiceAccount.setHelpText("Username of the service account. Needed for trigger challenge and token enrollment.");
        configProperties.add(emServiceAccount);

        ProviderConfigProperty emServicePass = new ProviderConfigProperty();
        emServicePass.setType(ProviderConfigProperty.PASSWORD);
        emServicePass.setName(Const.CONFIG_SERVICE_PASS);
        emServicePass.setLabel("Service account password");
        emServicePass.setHelpText("Password of the service account. Needed for trigger challenge and token enrollment.");
        configProperties.add(emServicePass);

        ProviderConfigProperty emServiceRealm = new ProviderConfigProperty();
        emServiceRealm.setType(ProviderConfigProperty.STRING_TYPE);
        emServiceRealm.setName(Const.CONFIG_SERVICE_REALM);
        emServiceRealm.setLabel("Service account realm");
        emServiceRealm.setHelpText("Realm of the service account, if it is in a separate realm from the other accounts. " +
                                   "Leave empty to use the general realm specified or the default realm if no realm is configured at all.");
        configProperties.add(emServiceRealm);

        ProviderConfigProperty emDoSendPassword = new ProviderConfigProperty();
        emDoSendPassword.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emDoSendPassword.setName(Const.CONFIG_SEND_PASSWORD);
        emDoSendPassword.setLabel("Send password");
        emDoSendPassword.setHelpText(
                "Choose if you want to send the password from the first login step to eduMFA. This can be used to trigger challenge-response token. " +
                "This setting is mutually exclusive with trigger challenge and sending a static pass.");
        configProperties.add(emDoSendPassword);

        ProviderConfigProperty emSendStaticPass = new ProviderConfigProperty();
        emSendStaticPass.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emSendStaticPass.setName(Const.CONFIG_SEND_STATIC_PASS);
        emSendStaticPass.setLabel("Send static password");
        emSendStaticPass.setHelpText("Enable to send the specified static password to eduMFA. Mutually exclusive with sending the password and trigger challenge.");
        configProperties.add(emSendStaticPass);

        ProviderConfigProperty emStaticPass = new ProviderConfigProperty();
        emStaticPass.setType(ProviderConfigProperty.PASSWORD);
        emStaticPass.setName(Const.CONFIG_STATIC_PASS);
        emStaticPass.setLabel("Static pass");
        emStaticPass.setHelpText("Set the static password which should be sent to eduMFA if \"send static password\" is enabled. " +
                                 "Can be empty to send an empty password.");
        configProperties.add(emStaticPass);

        ProviderConfigProperty emIncludeGroups = new ProviderConfigProperty();
        emIncludeGroups.setType(ProviderConfigProperty.STRING_TYPE);
        emIncludeGroups.setName(Const.CONFIG_INCLUDED_GROUPS);
        emIncludeGroups.setLabel("Included groups");
        emIncludeGroups.setHelpText(
                "Set groups for which the eduMFA workflow will be activated. The names should be separated with ',' (E.g. group1,group2)");
        configProperties.add(emIncludeGroups);

        ProviderConfigProperty emExcludeGroups = new ProviderConfigProperty();
        emExcludeGroups.setType(ProviderConfigProperty.STRING_TYPE);
        emExcludeGroups.setName(Const.CONFIG_EXCLUDED_GROUPS);
        emExcludeGroups.setLabel("Excluded groups");
        emExcludeGroups.setHelpText(
                "Set groups for which the eduMFA workflow will be skipped. The names should be separated with ',' (E.g. group1,group2). " +
                "If chosen group is already set in 'Included groups', excluding for this group will be ignored.");
        configProperties.add(emExcludeGroups);

        ProviderConfigProperty emDefaultOTPText = new ProviderConfigProperty();
        emDefaultOTPText.setType(ProviderConfigProperty.STRING_TYPE);
        emDefaultOTPText.setName(Const.CONFIG_DEFAULT_MESSAGE);
        emDefaultOTPText.setLabel("Default OTP Text");
        emDefaultOTPText.setHelpText(
                "Set the default OTP text that will be shown if no challenge or error messages are present.");
        configProperties.add(emDefaultOTPText);

        ProviderConfigProperty emOtpLength = new ProviderConfigProperty();
        emOtpLength.setType(ProviderConfigProperty.STRING_TYPE);
        emOtpLength.setName(Const.CONFIG_OTP_LENGTH);
        emOtpLength.setLabel("Auto-Submit OTP Length");
        emOtpLength.setHelpText("Automatically submit the login form after X digits were entered. Leave empty to disable. NOTE: Only digits can be entered!");
        configProperties.add(emOtpLength);

        ProviderConfigProperty emForwardedHeaders = new ProviderConfigProperty();
        emForwardedHeaders.setType(ProviderConfigProperty.STRING_TYPE);
        emForwardedHeaders.setName(Const.CONFIG_FORWARDED_HEADERS);
        emForwardedHeaders.setLabel("Headers to forward");
        emForwardedHeaders.setHelpText(
                "Set the headers which should be forwarded to eduMFA. If the header does not exist or has no value, it will be ignored. " +
                "The headers should be separated with ','.");
        configProperties.add(emForwardedHeaders);

        ProviderConfigProperty emEnrollToken = new ProviderConfigProperty();
        emEnrollToken.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emEnrollToken.setName(Const.CONFIG_ENROLL_TOKEN);
        emEnrollToken.setLabel("Enable token enrollment");
        emEnrollToken.setHelpText(
                "If enabled, the user gets a token enrolled automatically for them, if they do not have one yet. This requires a service account.");
        emEnrollToken.setDefaultValue("false");
        configProperties.add(emEnrollToken);

        List<String> tokenTypes = Arrays.asList("HOTP", "TOTP");
        ProviderConfigProperty emTokenType = new ProviderConfigProperty();
        emTokenType.setType(ProviderConfigProperty.LIST_TYPE);
        emTokenType.setName(Const.CONFIG_ENROLL_TOKEN_TYPE);
        emTokenType.setLabel("Enrollment token type");
        emTokenType.setHelpText("Select the token type that users can enroll, if they do not have a token yet. Service account is needed.");
        emTokenType.setOptions(tokenTypes);
        emTokenType.setDefaultValue(tokenTypes.get(0));
        configProperties.add(emTokenType);

        ProviderConfigProperty emPollInBrowser = new ProviderConfigProperty();
        emPollInBrowser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emPollInBrowser.setName(Const.CONFIG_POLL_IN_BROWSER);
        emPollInBrowser.setLabel("Poll in browser");
        emPollInBrowser.setDefaultValue(false);
        emPollInBrowser.setHelpText(
                "Enable this to do the polling for accepted push requests in the user's browser. "+
                "When enabled, the login page does not refresh when checking for successful push authentication. " +
                "NOTE: eduMFA has to be reachable from the user's browser and a valid SSL certificate has to be in place.");
        configProperties.add(emPollInBrowser);

        ProviderConfigProperty emPollInBrowserUrl = new ProviderConfigProperty();
        emPollInBrowserUrl.setType(ProviderConfigProperty.STRING_TYPE);
        emPollInBrowserUrl.setName(Const.CONFIG_POLL_IN_BROWSER_URL);
        emPollInBrowserUrl.setLabel("Url for poll in browser");
        emPollInBrowserUrl.setHelpText("Optional. If poll in browser should use a deviating URL, set it here. Otherwise, the general URL will be used.");
        configProperties.add(emPollInBrowserUrl);

        ProviderConfigProperty emPushTokenInterval = new ProviderConfigProperty();
        emPushTokenInterval.setType(ProviderConfigProperty.STRING_TYPE);
        emPushTokenInterval.setName(Const.CONFIG_PUSH_INTERVAL);
        emPushTokenInterval.setLabel("Push refresh interval");
        emPushTokenInterval.setHelpText(
                "Set the refresh interval for push tokens in seconds. Use a comma separated list. The last entry will be repeated.");
        configProperties.add(emPushTokenInterval);

        ProviderConfigProperty emDoLog = new ProviderConfigProperty();
        emDoLog.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        emDoLog.setName(Const.CONFIG_ENABLE_LOG);
        emDoLog.setLabel("Enable logging");
        emDoLog.setHelpText("If enabled, log messages will be written to the keycloak server logfile.");
        emDoLog.setDefaultValue("false");
        configProperties.add(emDoLog);
    }

    @Override
    public String getHelpText()
    {
        return "Authenticate the second factor against eduMFA.";
    }

    @Override
    public String getDisplayType()
    {
        return "eduMFA";
    }

    @Override
    public String getReferenceCategory()
    {
        return "eduMFA";
    }

    @Override
    public void init(Config.Scope config)
    {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory)
    {
    }

    @Override
    public void close()
    {
    }
}
