# encoding: UTF-8

control 'V-218827' do
  title "The IIS 10.0 web server must enable HTTP Strict Transport Security
(HSTS)."
  desc  "HTTP Strict Transport Security (HSTS) ensures browsers always connect
to a website over TLS. HSTS exists to remove the need for redirection
configurations. HSTS relies on the browser, web server, and a public
\"Whitelist\". If the browser does not support HSTS, it will be ignored."
  desc  'rationale', ''
  desc  'check', "
    Access the IIS 10.0 Web Server.

    Open IIS Manager.

    In the \"Connections\" pane, select the server name.

    In the \"Features View\" pane, open \"HTTP Response Headers\".

    Verify an entry exists named \"Strict-Transport-Security\".

    Open \"Strict-Transport-Security\" and verify the value box contains a
value greater than 0.

    Click \"OK\".

    If HSTS has not been enabled, this is a finding.
    The recommended max age is 8 minutes (480 seconds) or greater. Any value
greater than 0 is not a finding.
    If the version of Windows Server does not natively support HSTS, this is
not a finding.
  "
  desc  'fix', "
    Access the IIS 10.0 Web Server.

    Access an administrative command prompt and type the following commands,
substituting proper domain name:

    %systemroot%\\system32\\inetsrv\\appcmd.exe set config
-section:system.applicationHost/sites \"/[name='Contoso'].hsts.enabled:True\"
/commit:apphost
    %systemroot%\\system32\\inetsrv\\appcmd.exe set config
-section:system.applicationHost/sites \"/[name='Contoso'].hsts.max-age:480\"
/commit:apphost
    %systemroot%\\system32\\inetsrv\\appcmd.exe set config
-section:system.applicationHost/sites
\"/[name='Contoso'].hsts.includeSubDomains:True\" /commit:apphost
    %systemroot%\\system32\\inetsrv\\appcmd.exe set config
-section:system.applicationHost/sites
\"/[name='Contoso'].hsts.redirectHttpToHttps:True\" /commit:apphost
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-218827'
  tag rid: 'SV-218827r561041_rule'
  tag stig_id: 'IIST-SV-000205'
  tag fix_id: 'F-20297r505286_fix'
  tag cci: ['SV-109293', 'V-100189', 'CCI-000366']
  tag nist: ['CM-6 b']
end

