/*
* License:  AGPLv3
* This file is part of the eduMFA Keycloak extension. eduMFA Keycloak extension is a fork of privacyIDEA keycloak provider.
* Copyright (c) 2024 eduMFA Project-Team
* Previous authors of the PrivacyIDEA Keycloak provider:
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
import java.util.Map;

import static org.edumfa.authenticator.Const.CONFIG_DEFAULT_MESSAGE;
import static org.edumfa.authenticator.Const.CONFIG_ENABLE_LOG;
import static org.edumfa.authenticator.Const.CONFIG_ENROLL_TOKEN;
import static org.edumfa.authenticator.Const.CONFIG_ENROLL_TOKEN_TYPE;
import static org.edumfa.authenticator.Const.CONFIG_EXCLUDED_GROUPS;
import static org.edumfa.authenticator.Const.CONFIG_FORWARDED_HEADERS;
import static org.edumfa.authenticator.Const.CONFIG_INCLUDED_GROUPS;
import static org.edumfa.authenticator.Const.CONFIG_OTP_LENGTH;
import static org.edumfa.authenticator.Const.CONFIG_POLL_IN_BROWSER;
import static org.edumfa.authenticator.Const.CONFIG_POLL_IN_BROWSER_URL;
import static org.edumfa.authenticator.Const.CONFIG_PREF_TOKEN_TYPE;
import static org.edumfa.authenticator.Const.CONFIG_PUSH_INTERVAL;
import static org.edumfa.authenticator.Const.CONFIG_REALM;
import static org.edumfa.authenticator.Const.CONFIG_SEND_PASSWORD;
import static org.edumfa.authenticator.Const.CONFIG_TRIGGER_CHALLENGE;
import static org.edumfa.authenticator.Const.CONFIG_SERVER;
import static org.edumfa.authenticator.Const.CONFIG_SERVICE_ACCOUNT;
import static org.edumfa.authenticator.Const.CONFIG_SERVICE_PASS;
import static org.edumfa.authenticator.Const.CONFIG_SERVICE_REALM;
import static org.edumfa.authenticator.Const.CONFIG_SEND_STATIC_PASS;
import static org.edumfa.authenticator.Const.CONFIG_STATIC_PASS;
import static org.edumfa.authenticator.Const.CONFIG_VERIFY_SSL;
import static org.edumfa.authenticator.Const.DEFAULT_POLLING_ARRAY;
import static org.edumfa.authenticator.Const.DEFAULT_POLLING_INTERVAL;
import static org.edumfa.authenticator.Const.TRUE;

class Configuration
{
    private final String serverURL;
    private final String realm;
    private final boolean doSSLVerify;
    private final boolean doTriggerChallenge;
    private final boolean doSendPassword;
    private final boolean doSendStaticPass;
    private final String staticPass;
    private final String serviceAccountName;
    private final String serviceAccountPass;
    private final String serviceAccountRealm;
    private final List<String> excludedGroups = new ArrayList<>();
    private final List<String> includedGroups = new ArrayList<>();
    private final List<String> forwardedHeaders = new ArrayList<>();
    private final String otpLength;
    private final boolean doEnrollToken;
    private final boolean doLog;
    private final String enrollingTokenType;
    private final boolean pollInBrowser;
    private final String pollInBrowserUrl;
    private final List<Integer> pollingInterval = new ArrayList<>();
    private final String prefTokenType;
    private final int configHash;
    private final String defaultOTPMessage;

    Configuration(Map<String, String> configMap)
    {
        this.configHash = configMap.hashCode();
        this.serverURL = configMap.get(CONFIG_SERVER);
        this.realm = configMap.get(CONFIG_REALM) == null ? "" : configMap.get(CONFIG_REALM);
        this.doSSLVerify = configMap.get(CONFIG_VERIFY_SSL) != null && configMap.get(CONFIG_VERIFY_SSL).equals(TRUE);
        this.doTriggerChallenge = configMap.get(CONFIG_TRIGGER_CHALLENGE) != null && configMap.get(CONFIG_TRIGGER_CHALLENGE).equals(TRUE);
        this.serviceAccountName = configMap.get(CONFIG_SERVICE_ACCOUNT) == null ? "" : configMap.get(CONFIG_SERVICE_ACCOUNT);
        this.serviceAccountPass = configMap.get(CONFIG_SERVICE_PASS) == null ? "" : configMap.get(CONFIG_SERVICE_PASS);
        this.serviceAccountRealm = configMap.get(CONFIG_SERVICE_REALM) == null ? "" : configMap.get(CONFIG_SERVICE_REALM);
        this.staticPass = configMap.get(CONFIG_STATIC_PASS) == null ? "" : configMap.get(CONFIG_STATIC_PASS);
        this.defaultOTPMessage = configMap.get(CONFIG_DEFAULT_MESSAGE) == null ? "" : configMap.get(CONFIG_DEFAULT_MESSAGE);
        this.otpLength = configMap.get(CONFIG_OTP_LENGTH) == null ? "" : configMap.get(CONFIG_OTP_LENGTH);
        this.pollInBrowser = (configMap.get(CONFIG_POLL_IN_BROWSER) != null && configMap.get(CONFIG_POLL_IN_BROWSER).equals(TRUE));
        this.pollInBrowserUrl = configMap.get(CONFIG_POLL_IN_BROWSER_URL) == null ? "" : configMap.get(CONFIG_POLL_IN_BROWSER_URL);
        this.doEnrollToken = configMap.get(CONFIG_ENROLL_TOKEN) != null && configMap.get(CONFIG_ENROLL_TOKEN).equals(TRUE);
        this.doSendPassword = configMap.get(CONFIG_SEND_PASSWORD) != null && configMap.get(CONFIG_SEND_PASSWORD).equals(TRUE);
        this.doSendStaticPass = configMap.get(CONFIG_SEND_STATIC_PASS) != null && configMap.get(CONFIG_SEND_STATIC_PASS).equals(TRUE);
        // EM uses all lowercase letters for token types so change it here to match it internally
        this.prefTokenType = (configMap.get(CONFIG_PREF_TOKEN_TYPE) == null ? "otp" : configMap.get(CONFIG_PREF_TOKEN_TYPE)).toLowerCase();
        this.enrollingTokenType = (configMap.get(CONFIG_ENROLL_TOKEN_TYPE) == null ? "" : configMap.get(CONFIG_ENROLL_TOKEN_TYPE)).toLowerCase();
        this.doLog = configMap.get(CONFIG_ENABLE_LOG) != null && configMap.get(CONFIG_ENABLE_LOG).equals(TRUE);

        String excludedGroupsStr = configMap.get(CONFIG_EXCLUDED_GROUPS);
        if (excludedGroupsStr != null)
        {
            this.excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
        }

        String includedGroupsStr = configMap.get(CONFIG_INCLUDED_GROUPS);
        if (includedGroupsStr != null)
        {
            this.includedGroups.addAll(Arrays.asList(includedGroupsStr.split(",")));
        }

        String forwardedHeadersStr = configMap.get(CONFIG_FORWARDED_HEADERS);
        if (forwardedHeadersStr != null)
        {
            this.forwardedHeaders.addAll(Arrays.asList(forwardedHeadersStr.split(",")));
        }

        // Set intervals to either default or configured values
        String s = configMap.get(CONFIG_PUSH_INTERVAL);
        if (s != null)
        {
            List<String> strPollingIntervals = Arrays.asList(s.split(","));
            if (!strPollingIntervals.isEmpty())
            {
                this.pollingInterval.clear();
                for (String str : strPollingIntervals)
                {
                    try
                    {
                        this.pollingInterval.add(Integer.parseInt(str));
                    }
                    catch (NumberFormatException e)
                    {
                        this.pollingInterval.add(DEFAULT_POLLING_INTERVAL);
                    }
                }
            }
        }
        else
        {
            this.pollingInterval.addAll(DEFAULT_POLLING_ARRAY);
        }
    }

    int configHash()
    {
        return configHash;
    }

    String serverURL()
    {
        return serverURL;
    }

    String realm()
    {
        return realm;
    }

    boolean sslVerify()
    {
        return doSSLVerify;
    }

    boolean triggerChallenge()
    {
        return doTriggerChallenge;
    }

    boolean sendStaticPass()
    {
        return doSendStaticPass;
    }

    String staticPass()
    {
        return staticPass;
    }

    String serviceAccountName()
    {
        return serviceAccountName;
    }

    String serviceAccountPass()
    {
        return serviceAccountPass;
    }

    String serviceAccountRealm()
    {
        return serviceAccountRealm;
    }

    List<String> excludedGroups()
    {
        return excludedGroups;
    }

    List<String> includedGroups()
    {
        return includedGroups;
    }

    List<String> forwardedHeaders()
    {
        return forwardedHeaders;
    }

    String otpLength()
    {
        return otpLength;
    }

    boolean enrollToken()
    {
        return doEnrollToken;
    }

    String enrollingTokenType()
    {
        return enrollingTokenType;
    }

    boolean pollInBrowser()
    {
        return pollInBrowser;
    }

    String pollInBrowserUrl()
    {
        return pollInBrowserUrl;
    }

    List<Integer> pollingInterval()
    {
        return pollingInterval;
    }

    boolean doLog()
    {
        return doLog;
    }

    boolean sendPassword()
    {
        return doSendPassword;
    }

    String prefTokenType()
    {
        return prefTokenType;
    }

    String defaultOTPMessage()
    {
        return defaultOTPMessage;
    }
}
