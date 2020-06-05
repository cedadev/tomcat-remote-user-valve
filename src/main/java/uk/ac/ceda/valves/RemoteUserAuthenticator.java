/**
 * Copyright 2020 United Kingdom Research and Innovation
 *
 * Authors: William Tucker
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

package uk.ac.ceda.valves;

import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * A <b>Valve</b> <b>Authenticator</b> for Web-server-provided authentication.
 * 
 * If the request is not authenticated, then this <b>Valve</b> attempts to find
 * a username passed in the ``REMOTE_USER`` or ``X_REMOTE_USER`` request header.
 * If found, the user is automatically logged in. The user will also be given
 * any roles provided the ``X_REMOTE_USER_ROLES`` request header.
 */
public class RemoteUserAuthenticator extends AuthenticatorBase
{

    public static final String AUTH_METHOD = "REMOTE_USER";

    public static final String[] USERNAME_HEADERS = { "remote-user", "x-remote-user" };
    public static final String ROLES_HEADER = "x-remote-user-roles";

    private final Log log = LogFactory.getLog(RemoteUserAuthenticator.class);

    /**
     * Authenticate the user making this request based on the presence of a required
     * header. Return <code>true</code> if a remote user was discovered or the user
     * is already authenticated. Return <code>false</code> if no condition is met.
     *
     * @param request  Request we are processing
     * @param response Response we are creating
     * @param config   Login configuration describing how authentication should be
     *                 performed
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    public boolean authenticate(Request request, HttpServletResponse response,
            LoginConfig loginConfig) throws IOException
    {
        // Have we already authenticated someone?
        Principal principal = ((HttpServletRequest) request.getRequest()).getUserPrincipal();
        if (principal != null)
        {
            if (log.isDebugEnabled())
                log.debug(String.format("Already authenticated '%s'", principal.getName()));

            return true;
        }

        // Retrieve username from the request preferring the first available header
        String username = null;
        for (String header : RemoteUserAuthenticator.USERNAME_HEADERS)
        {
            username = request.getHeader(header);
            if (isValidUsername(username))
                break;
        }

        // Have we found a trusted user?
        if (isValidUsername(username))
        {
            // Get all roles associated with this user from the request
            List<String> roles = Collections
                    .list(request.getHeaders(RemoteUserAuthenticator.ROLES_HEADER));

            if (log.isDebugEnabled())
                log.debug(String.format("Found remote user '%s' with roles: %s", username, roles));

            // Create a new principal to represent the remote user
            principal = new GenericPrincipal(username, null, roles);
            register(request, response, principal, RemoteUserAuthenticator.AUTH_METHOD, username,
                    null);

            return true;
        }

        return false;
    }

    /**
     * Check if the username from the header is valid. Return <code>true</code> if
     * valid and <code>false</code> if not.
     *
     * @param username The username from the request header
     */
    protected boolean isValidUsername(String username)
    {
        return (username != null && username.length() > 0);
    }

    @Override
    protected String getAuthMethod()
    {
        return RemoteUserAuthenticator.AUTH_METHOD;
    }

}
