# encoding: UTF-8

control 'V-218825' do
  title "The IIS 10.0 web server must have a global authorization rule
configured to restrict access."
  desc  "Authorization rules can be configured at the server, website, folder
(including Virtual Directories), or file level. It is recommended that URL
Authorization be configured to only grant access to the necessary security
principals. Configuring a global Authorization rule that restricts access
ensures inheritance of the settings down through the hierarchy of web
directories. This will ensure access to current and future content is only
granted to the appropriate principals, mitigating risk of unauthorized access. "
  desc  'rationale', ''
  desc  'check', "
    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Double-click the \".NET Authorization Rules\" icon.

    If any user other than \"Administrator\" is listed, this is a finding.

    If .NET is not installed, this is Not Applicable.
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Double-click the \"Authorization Rules\" icon.

    Remove all users other than \"Administrator\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-218825'
  tag rid: 'SV-218825r561041_rule'
  tag stig_id: 'IIST-SV-000159'
  tag fix_id: 'F-20295r310951_fix'
  tag cci: ['SV-109289', 'V-100185', 'CCI-000366']
  tag nist: ['CM-6 b']

  anonymousAuthentication = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled | select -expandProperty value').stdout.strip == 'False'
  basicAuthentication = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/basicAuthentication" -Name enabled | select -expandProperty value').stdout.strip == 'True'
  defaultLogonDomain = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/basicAuthentication" -Name defaultLogonDomain | select -expandProperty value').stdout.strip == 'Administrator'

  describe 'The IIS 10 web server must have a global authorization rule configured to restrict access to anonymousAuthentication by disabling it. (currently: ' + (anonymousAuthentication ? 'disabled' : 'enabled') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled | select -expandProperty value').stdout.strip }
    it 'The anonymousAuthentication should be false' do
      expect(subject).to cmp('false')
    end
  end
  describe 'The IIS 10 web server must have a global authorization rule configured to restrict access to basicAuthentication, this attribute should be enabled. (currently: ' + (basicAuthentication ? 'enabled' : 'disabled') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/basicAuthentication" -Name enabled | select -expandProperty value').stdout.strip }
    it 'The basicAuthentication should be enabled' do
      expect(subject).to cmp('true')
    end
  end
  describe 'The IIS 10 web server must have a global authorization rule configured to restrict access to basicAuthentication attribute defaultLogonDomain, this attribute should be set to Administrator only. (currently: ' + (defaultLogonDomain ? 'Administrator' : 'Other') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/basicAuthentication" -Name defaultLogonDomain | select -expandProperty value').stdout.strip }
    it 'The basicAuthentication attribute defaultLogonDomain should be Administrator' do
      expect(subject).to cmp('Administrator')
    end
  end

end

