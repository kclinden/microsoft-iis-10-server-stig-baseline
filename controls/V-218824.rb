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

  isInstalledIsapiCGI = !command('Get-WindowsFeature Web-ISAPI-Ext | Where Installed').stdout.strip.nil?
  notListedCgisAllowed = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedCgisAllowed | select -expandProperty value').stdout.strip == 'False'
  notListedIsapisAllowed = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedIsapisAllowed | select -expandProperty value').stdout.strip == 'False'

  describe 'The ISAPI and CGI restrictions feature must be installed. (currently: ' + (isInstalledIsapiCGI ? 'installed' : 'uninstalled') + " )\n" do
    subject { windows_feature('Web-ISAPI-Ext') }
    it 'The ISAPI and CGI restrictions should be installed' do
      expect(subject).to be_installed
    end
  end
  describe 'The ISAPI and CGI restrictions for notListedCgisAllowed must not be enabled. (currently: ' + (notListedCgisAllowed ? 'disabled' : 'enabled') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedCgisAllowed | select -expandProperty value').stdout.strip }
    it 'The ISAPI and CGI restrictions attribute notListedCgisAllowed should not be checked' do
      expect(subject).to cmp('False')
    end
  end
  describe 'The ISAPI and CGI restrictions for notListedIsapisAllowed must not be enabled. (currently: ' + (notListedIsapisAllowed ? 'disabled' : 'enabled') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedIsapisAllowed | select -expandProperty value').stdout.strip }
    it 'The ISAPI and CGI restrictions attribute notListedIsapisAllowed should not be checked' do
      expect(subject).to cmp('False')
    end
  end

end

