/*
* License:  AGPLv3
* This file is part of the eduMFA Keycloak extension. eduMFA Keycloak extension is a fork of eduMFA keycloak provider.
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

import org.edumfa.EduMFA;

public class Pair
{
    private final EduMFA eduMFA;
    private final Configuration configuration;

    public Pair(EduMFA eduMFA, Configuration configuration)
    {
        this.eduMFA = eduMFA;
        this.configuration = configuration;
    }

    public EduMFA eduMFA()
    {
        return eduMFA;
    }

    public Configuration configuration()
    {
        return configuration;
    }
}
