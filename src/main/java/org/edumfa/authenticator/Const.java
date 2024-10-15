/*
* License:  AGPLv3
* This file is part of the eduMFA Keycloak extension. eduMFA Keycloak extension is a fork of privacyIDEA keycloak provider.
* Copyright (c) 2024 eduMFA Project-Team
* Previous authors of the PrivacyIDEA java client:
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

import java.util.Arrays;
import java.util.List;

final class Const
{
    private Const()
    {
    }

    static final String PROVIDER_ID = "edumfa-authenticator";
    static final String PLUGIN_USER_AGENT = "eduMFA-Keycloak";

    static final String DEFAULT_PUSH_MESSAGE_EN = "Please confirm the authentication on your mobile device!";
    static final String DEFAULT_PUSH_MESSAGE_DE = "Bitte bestätigen Sie die Authentifizierung auf ihrem Smartphone!";

    static final String DEFAULT_OTP_MESSAGE_EN = "Please enter your One-Time-Password!";
    static final String DEFAULT_OTP_MESSAGE_DE = "Bitte geben Sie ihr Einmalpasswort ein!";

    static final String TRUE = "true";

    static final String HEADER_ACCEPT_LANGUAGE = "accept-language";
    // Will be used if single value from config cannot be parsed
    static final int DEFAULT_POLLING_INTERVAL = 2;
    // Will be used if no intervals are specified
    static final List<Integer> DEFAULT_POLLING_ARRAY = Arrays.asList(4, 2, 2, 2, 3);

    static final String FORM_POLL_INTERVAL = "pollingInterval";
    static final String FORM_TOKEN_ENROLLMENT_QR = "tokenEnrollmentQR";
    static final String FORM_MODE = "mode";
    static final String FORM_IMAGE_PUSH = "pushImage";
    static final String FORM_IMAGE_OTP = "otpImage";
    static final String FORM_IMAGE_WEBAUTHN = "webauthnImage";
    static final String FORM_POLL_IN_BROWSER_FAILED = "pollInBrowserFailed";
    static final String FORM_ERROR_MESSAGE = "errorMsg";
    static final String FORM_TRANSACTION_ID = "transactionID";
    static final String FORM_PI_SERVER_URL = "emServerUrl";
    static final String FORM_AUTO_SUBMIT_OTP_LENGTH = "AutoSubmitOtpLength";
    static final String FORM_PI_POLL_IN_BROWSER_URL = "emPollInBrowserUrl";
    static final String FORM_PUSH_AVAILABLE = "push_available";
    static final String FORM_OTP_AVAILABLE = "otp_available";
    static final String FORM_PUSH_MESSAGE = "pushMessage";
    static final String FORM_OTP_MESSAGE = "otpMessage";
    static final String FORM_FILE_NAME = "eduMFA.ftl";
    static final String FORM_MODE_CHANGED = "modeChanged";
    static final String FORM_OTP = "otp";
    static final String FORM_UI_LANGUAGE = "uilanguage";
    static final String FORM_ERROR = "hasError";

    // Webauthn form fields
    static final String FORM_WEBAUTHN_SIGN_REQUEST = "webauthnsignrequest";
    static final String FORM_WEBAUTHN_SIGN_RESPONSE = "webauthnsignresponse";
    static final String FORM_WEBAUTHN_ORIGIN = "origin";

    // U2F form fields
    static final String FORM_U2F_SIGN_REQUEST = "u2fsignrequest";
    static final String FORM_U2F_SIGN_RESPONSE = "u2fsignresponse";

    static final String AUTH_NOTE_TRANSACTION_ID = "transaction_id";
    static final String AUTH_NOTE_AUTH_COUNTER = "authCounter";
    static final String AUTH_NOTE_ACCEPT_LANGUAGE = "authLanguage";

    // Changing the config value names will reset the current config
    static final String CONFIG_PUSH_INTERVAL = "empushtokeninterval";
    static final String CONFIG_EXCLUDED_GROUPS = "emexcludegroups";
    static final String CONFIG_INCLUDED_GROUPS = "emincludegroups";
    static final String CONFIG_FORWARDED_HEADERS = "emforwardedheaders";
    static final String CONFIG_ENROLL_TOKEN_TYPE = "emenrolltokentype";
    static final String CONFIG_ENROLL_TOKEN = "emenrolltoken";
    static final String CONFIG_DEFAULT_MESSAGE = "emdefaultmessage";
    static final String CONFIG_POLL_IN_BROWSER = "empollinbrowser";
    static final String CONFIG_POLL_IN_BROWSER_URL = "empollinbrowserurl";
    static final String CONFIG_SEND_PASSWORD = "emsendpassword";
    static final String CONFIG_TRIGGER_CHALLENGE = "emdotriggerchallenge";
    static final String CONFIG_SEND_STATIC_PASS = "emsendstaticpass";
    static final String CONFIG_OTP_LENGTH = "emotplength";
    static final String CONFIG_SERVICE_PASS = "emservicepass";
    static final String CONFIG_SERVICE_ACCOUNT = "emserviceaccount";
    static final String CONFIG_SERVICE_REALM = "emservicerealm";
    static final String CONFIG_STATIC_PASS = "emstaticpass";
    static final String CONFIG_VERIFY_SSL = "emverifyssl";
    static final String CONFIG_REALM = "emrealm";
    static final String CONFIG_SERVER = "emserver";
    static final String CONFIG_ENABLE_LOG = "emdolog";
    static final String CONFIG_PREF_TOKEN_TYPE = "preftokentype";
}
