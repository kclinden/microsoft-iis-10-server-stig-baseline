# encoding: UTF-8

control 'V-218824' do
  title "Unspecified file extensions on a production IIS 10.0 web server must
be removed."
  desc  "By allowing unspecified file extensions to execute, the web servers
attack surface is significantly increased. This increased risk can be reduced
by only allowing specific ISAPI extensions or CGI extensions to run on the web
server."
  desc  'rationale', ''
  desc  'check', "
    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Double-click the \"ISAPI and CGI restrictions\" icon.

    Click “Edit Feature Settings\".

    Verify the \"Allow unspecified CGI modules\" and the \"Allow unspecified
ISAPI modules\" check boxes are NOT checked.

    If either or both of the \"Allow unspecified CGI modules\" and the \"Allow
unspecified ISAPI modules\" check boxes are checked, this is a finding.
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Double-click the \"ISAPI and CGI restrictions\" icon.

    Click \"Edit Feature Settings\".

    Remove the check from the \"Allow unspecified CGI modules\" and the \"Allow
unspecified ISAPI modules\" check boxes.

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-218824'
  tag rid: 'SV-218824r561041_rule'
  tag stig_id: 'IIST-SV-000158'
  tag fix_id: 'F-20294r310948_fix'
  tag cci: ['V-100183', 'SV-109287', 'CCI-000366']
  tag nist: ['CM-6 b']
end

