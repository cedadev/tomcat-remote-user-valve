# Tomcat remote user Valve

A Valve providing Web-server-provided authentication for a Tomcat server. Required Tomcat 8.5.

The Valve can be used to authenticate requests in Tomcat based on the presence of a REMOTE_USER or X_REMOTE_USER header in the
request (when both headers are present, REMOTE_USER is preferred). The authenticated user can also be assigned roles by attaching
them with an X_REMOTE_USER_ROLES header.

Existing users defined in the `tomcat-users.xml` file will be ignored. Separate users with separate groups are created instead.

## How to use

1. Place the Valve's .jar file inside the `lib` directory of your Tomcat server installation.

2. Add the following to the "<Context>" element of your web application's `context.xml` file:

```xml
    <Valve className="uk.ac.ceda.valves.RemoteUserAuthenticator" />
```

3. Ensure that your "<web-app>" in `web.xml` has been configured with an appropriate security constraints. Here is an example:

```xml
    <security-constraint>
        <web-resource-collection>
            <web-resource-name>Everything</web-resource-name>
            <url-pattern>/*</url-pattern>
            <http-method>GET</http-method>
            <http-method>POST</http-method>
        </web-resource-collection>
        <auth-constraint>
            <role-name>some-special-role</role-name>
        </auth-constraint>

        <user-data-constraint>
            <transport-guarantee>NONE</transport-guarantee>
        </user-data-constraint>
    </security-constraint>
```
