# encoding: UTF-8

control 'V-218794' do
  title "The IIS 10.0 web server must not be both a website server and a proxy
server."
  desc  "A web server should be primarily a web server or a proxy server but
not both, for the same reasons that other multi-use servers are not
recommended. Scanning for web servers that also proxy requests into an
otherwise protected network is a common attack, making the attack anonymous."
  desc  'rationale', ''
  desc  'check', "
    Open the IIS 10.0 Manager.

    Under the \"Connections\" pane on the left side of the management console,
select the IIS 10.0 web server.

    If, under the IIS installed features, \"Application Request Routing Cache\"
is not present, this is not a finding.

    If, under the IIS installed features, \"Application Request Routing Cache\"
is present, double-click the icon to open the feature.

    From the right \"Actions\" pane, under \"Proxy\", select \"Server Proxy
Settings...\".

    In the \"Application Request Routing\" settings window, verify whether
\"Enable proxy\" is selected.

    If “Enable proxy\" is selected under the \"Application Request Routing\"
settings, this is a finding.
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Under the \"Connections\" pane on the left side of the management console,
select the IIS 10.0 web server.

    Under the IIS installed features, \"Application Request Routing Cache\" is
present, double-click the icon to open the feature.

    From the right \"Actions\" pane, under \"Proxy\", select \"Server Proxy
Settings...\".

    In the \"Application Request Routing\" settings window, remove the check
from the \"Enable proxy\" check box.

    Click \"Apply\" in the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag gid: 'V-218794'
  tag rid: 'SV-218794r561041_rule'
  tag stig_id: 'IIST-SV-000119'
  tag fix_id: 'F-20264r310858_fix'
  tag cci: ['SV-109227', 'V-100123', 'CCI-000381']
  tag nist: ['CM-7 a']

  is_proxy_server = input('is_proxy')
  proxy_checkbox = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/proxy" -name "enabled" | select -ExpandProperty Value').stdout.strip
  proxy_enabled = proxy_checkbox == 'False' || proxy_checkbox == '' ? false : true

  if is_proxy_server
    describe windows_feature('Web-Server') do
      it { should be_installed }
    end
    describe windows_feature('Web-WebServer') do
      it { should be_installed }
    end
    describe windows_feature('Web-Common-Http') do
      it { should be_installed }
    end

    describe 'Running as a proxy-server, the ARR proxy should be enabled ' do
      subject { proxy_enabled }
      it { should be true }
    end
  else
    describe windows_feature('Web-Server') do
      it { should be_installed }
    end
    describe windows_feature('Web-WebServer') do
      it { should be_installed }
    end
    describe windows_feature('Web-Common-Http') do
      it { should be_installed }
    end
    describe 'Running as a web-server, the ARR Server Proxy should not be enabled ' do
      subject { proxy_enabled }
      it { should be false }
    end
  end

end

