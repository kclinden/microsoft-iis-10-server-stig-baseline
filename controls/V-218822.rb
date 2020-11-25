# encoding: UTF-8

control 'V-218822' do
  title "The IIS 10.0 web server must maintain the confidentiality of
controlled information during transmission through the use of an approved
Transport Layer Security (TLS) version."
  desc  "TLS is a required transmission protocol for a web server hosting
controlled information. The use of TLS provides confidentiality of data in
transit between the web server and client. FIPS 140-2-approved TLS versions
must be enabled and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government
applications.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the web server documentation and deployed configuration to determine
which version of TLS is being used.

    If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52,
or if non-FIPS-approved algorithms are enabled, this is a finding.
  "
  desc  'fix', "Configure the web server to use an approved TLS version
according to NIST SP 800-52 and to disable all non-approved versions."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag gid: 'V-218822'
  tag rid: 'SV-218822r561041_rule'
  tag stig_id: 'IIST-SV-000154'
  tag fix_id: 'F-20292r310942_fix'
  tag cci: ['V-100179', 'SV-109283', 'CCI-002418']
  tag nist: ['SC-8']

  tls1_1Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client').Enabled
  tls1_2Enabled = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client').Enabled

  describe.one do
    describe 'The web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version such as TLS 1.1. (currently: ' + (tls1_1Enabled ? 'TLS 1.1 enabled' : 'Other enabled') + " )\n" do
      subject { tls1_1Enabled }
      it 'TLS 1.1 should be enabled' do
        expect(subject).to cmp('1')
      end
    end
    describe 'The web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version such as TLS 1.2. (currently: ' + (tls1_2Enabled ? 'TLS 1.2 enabled' : 'Other enabled') + " )\n" do
      subject { tls1_2Enabled }
      it 'TLS 1.2 should be enabled' do
        expect(subject).to cmp('1')
      end
    end
  end

end

