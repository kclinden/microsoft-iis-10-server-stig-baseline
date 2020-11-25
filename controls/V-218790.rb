# encoding: UTF-8

control 'V-218790' do
  title "The log information from the IIS 10.0 web server must be protected
from unauthorized modification or deletion."
  desc  "A major tool in exploring the website use, attempted use, unusual
conditions, and problems are the access and error logs. In the event of a
security incident, these logs can provide the System Administrator (SA) and the
web manager with valuable information. Failure to protect log files could
enable an attacker to modify the log file data or falsify events to mask an
attacker's activity.


  "
  desc  'rationale', ''
  desc  'check', "
    This check does not apply to service account IDs utilized by automated
services necessary to process, manage, and store log files.
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Click the \"Logging\" icon.
    Click \"Browse\" and navigate to the directory where the log files are
stored.
    Right-click the log file directory to review.
    Click \"Properties\".
    Click the \"Security\" tab.
    Verify log file access is restricted as follows. Otherwise, this is a
finding.
    SYSTEM - Full Control
    Administrators - Full Control
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Click the \"Logging\" icon.

    Click \"Browse\" and navigate to the directory where the log files are
stored.

    Right-click the log file directory to review and click \"Properties\".

    Click the \"Security\" tab.

    Set the log file permissions for the appropriate group(s).

    Click \"OK\".

    Select \"Apply\" in the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag satisfies: ['SRG-APP-000120-WSR-000070', 'SRG-APP-000118-WSR-000068',
'SRG-APP-000118-WSR-000069']
  tag gid: 'V-218790'
  tag rid: 'SV-218790r561041_rule'
  tag stig_id: 'IIST-SV-000115'
  tag fix_id: 'F-20260r539450_fix'
  tag cci: ['SV-109219', 'V-100115', 'CCI-000164']
  tag nist: ['AU-9']

  #This should be automated in the future...
  describe 'Manual review of web server is required.' do
    skip 'Manual review of web server is required'
  end

end

