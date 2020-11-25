# encoding: UTF-8

control 'V-218791' do
  title "The log data and records from the IIS 10.0 web server must be backed
up onto a different system or media."
  desc  "Protection of log data includes ensuring log data is not accidentally
lost or deleted. Backing up log records to an unrelated system, or onto
separate media than the system on which the web server is running, helps to
ensure the log records will be retained in the event of a catastrophic system
failure."
  desc  'rationale', ''
  desc  'check', "
    The IIS 10.0 web server and website log files should be backed up by the
system backup.

    To determine if log files are backed up by the system backup, determine the
location of the web server log files and each website's log files.

    Open the IIS 10.0 Manager.

    Click the IIS 10.0 server name.

    Click the \"Logging\" icon.

    Under \"Log File\" >> \"Directory\" obtain the path of the log file.

    Once all locations are known, consult with the System Administrator to
review the server's backup procedure and policy.

    Verify the paths of all log files are part of the system backup.
    Verify log files are backed up to an unrelated system or onto separate
media on which the system the web server is running.

    If the paths of all log files are not part of the system backup and/or not
backed up to a separate media, this is a finding.
  "
  desc  'fix', "Configure system backups to include the directory paths of all
IIS 10.0 web server and website log files."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag gid: 'V-218791'
  tag rid: 'SV-218791r561041_rule'
  tag stig_id: 'IIST-SV-000116'
  tag fix_id: 'F-20261r310849_fix'
  tag cci: ['V-100117', 'SV-109221', 'CCI-001348']
  tag nist: ['AU-9 (2)']
end

