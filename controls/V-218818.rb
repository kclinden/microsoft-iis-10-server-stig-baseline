# encoding: UTF-8

control 'V-218818' do
  title "The Internet Printing Protocol (IPP) must be disabled on the IIS 10.0
web server."
  desc  "The use of IPP on an IIS web server allows client access to shared
printers. This privileged access could allow remote code execution by
increasing the web servers attack surface. Additionally, since IPP does not
support SSL, it is considered a risk and will not be deployed."
  desc  'rationale', ''
  desc  'check', "
    If the Print Services role and the Internet Printing role are not
installed, this check is Not Applicable.

    Navigate to the following directory:

    %windir%\\web\\printers

    If this folder exists, this is a finding.

    Determine whether Internet Printing is enabled:

    Click “Start”, click “Administrative Tools”, and then click “Server
Manager”.

    Expand the roles node, right-click “Print Services”, and then select
“Remove Roles Services”.

    If the Internet Printing option is enabled, this is a finding.
  "
  desc  'fix', "
    Click “Start”, click “Administrative Tools”, and then click “Server
Manager”.

    Expand the roles node, right-click “Print Services”, and then select
“Remove Roles Services”.

    If the Internet Printing option is checked, clear the check box, click
“Next”, and then click “Remove” to complete the wizard.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-218818'
  tag rid: 'SV-218818r561041_rule'
  tag stig_id: 'IIST-SV-000149'
  tag fix_id: 'F-20288r310930_fix'
  tag cci: ['V-100171', 'SV-109275', 'CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe directory('%windir%\web\printers') do
    it { should_not exist }
  end

  describe windows_feature('Print-Services') do
    it { should_not be_installed }
  end

end

