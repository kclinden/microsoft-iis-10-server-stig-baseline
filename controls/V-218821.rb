# encoding: UTF-8

control 'V-218821' do
  title "An IIS 10.0 web server must maintain the confidentiality of controlled
information during transmission through the use of an approved Transport Layer
Security (TLS) version."
  desc  "TLS encryption is a required security setting for a private web
server. Encryption of private information is essential to ensuring data
confidentiality. If private information is not encrypted, it can be intercepted
and easily read by an unauthorized party. A private web server must use a FIPS
140-2-approved TLS version, and all non-FIPS-approved SSL versions must be
disabled.

    NIST SP 800-52 specifies the preferred configurations for government
systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Access the IIS 10.0 Web Server.

    Access an administrator command prompt and type \"regedit <enter>\" to
access the server's registry.

    Navigate to:

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.2\\Server

    Verify a REG_DWORD value of \"0\" for \"DisabledByDefault\"

    Navigate to:

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.0\\Server


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.1\\Server


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
2.0\\Server


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
3.0\\Server

    Verify a REG_DWORD value of \"1\" for \"DisabledByDefault\"
    Verify a REG_DWORD value of \"0\" for \"Enabled\"

    If any of the respective registry paths do not exist or are configured with
the wrong value, this is a finding.
  "
  desc  'fix', "
    Access the IIS 10.0 Web Server.

    Access an administrator command prompt and type \"regedit <enter>\" to
access the server's registry.

    Navigate to the following registry paths and configure the
\"DisabledByDefault\" REG_DWORD with the appropriate values:


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.2\\Server

    With a REG_DWORD value of \"0\" for \"DisabledByDefault\"


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.0\\Server


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.1\\Server


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
2.0\\Server


HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
3.0\\Server

    With a REG_DWORD value of \"1\" for \"DisabledByDefault\"

    With a REG_DWORD value of \"0\" for \"Enabled\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag gid: 'V-218821'
  tag rid: 'SV-218821r561041_rule'
  tag stig_id: 'IIST-SV-000153'
  tag fix_id: 'F-20291r505283_fix'
  tag cci: ['V-100177', 'SV-109281', 'CCI-002418']
  tag nist: ['SC-8']

  tls1_1Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').DisabledByDefault == 0
  tls1_2Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').DisabledByDefault == 0
  tls1_0Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').DisabledByDefault == 1
  ssl2_0Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').DisabledByDefault == 1
  ssl3_0Disabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client').DisabledByDefault == 1

  describe 'An IIS 10 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.1 should not be DisabledByDefault. (currently: TLS 1.1 ' + (tls1_1Disabled ? 'not DisabledByDefault' : 'DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').DisabledByDefault }
    it 'TLS 1.1 DisabledByDefault should eq 0' do
      expect(subject).to cmp('0')
    end
  end
  describe 'An IIS 10 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.2 should not be DisabledByDefault. (currently: TLS 1.2 ' + (tls1_2Disabled ? 'not DisabledByDefault' : 'DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').DisabledByDefault }
    it 'TLS 1.2 DisabledByDefault should eq 0' do
      expect(subject).to cmp('0')
    end
  end
  describe 'An IIS 10 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, TLS 1.0 should be DisabledByDefault. (currently: TLS 1.0 ' + (tls1_0Disabled ? 'DisabledByDefault' : 'not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client').DisabledByDefault }
    it 'TLS 1.0 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end
  describe 'An IIS 10 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, SSL 2.0 should be DisabledByDefault. (currently: SSL 2.0 ' + (ssl2_0Disabled ? 'DisabledByDefault' : 'not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client').DisabledByDefault }
    it 'SSL 2.0 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end
  describe 'An IIS 10 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version, SSL 3.0 should be DisabledByDefault. (currently: SSL 3.0 ' + (ssl3_0Disabled ? 'DisabledByDefault' : 'not DisabledByDefault') + " )\n" do
    subject { registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client').DisabledByDefault }
    it 'SSL 3.0 DisabledByDefault should eq 1' do
      expect(subject).to cmp('1')
    end
  end

end

