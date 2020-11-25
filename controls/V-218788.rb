# encoding: UTF-8

control 'V-218788' do
  title "The IIS 10.0 web server must produce log records that contain
sufficient information to establish the outcome (success or failure) of IIS
10.0 web server events."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the success or failure of an event is important during
forensic analysis. Correctly determining the outcome will add information to
the overall reconstruction of the loggable event. By determining the success or
failure of the event correctly, analysis of the enterprise can be undertaken to
determine if events tied to the event occurred in other areas within the
enterprise.

    Without sufficient information establishing the success or failure of the
logged event, investigation into the cause of event is severely hindered. The
success or failure also provides a means to measure the impact of an event and
help authorized personnel determine the appropriate response. Log record
content that may be necessary to satisfy the requirement of this control
includes, but is not limited to, time stamps, source and destination IP
addresses, user/process identifiers, event descriptions, application-specific
events, success/fail indications, file names involved, access control, or flow
control rules invoked.
  "
  desc  'rationale', ''
  desc  'check', "
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under \"IIS\", double-click the \"Logging\" icon.
    Verify the \"Format:\" under \"Log File\" is configured to \"W3C\".
    Select the \"Fields\" button.
    Under \"Custom Fields\", verify the following fields have been configured:
    Request Header >> Connection
    Request Header >> Warning
    If any of the above fields are not selected, this is a finding.
  "
  desc  'fix', "
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under \"IIS\", double-click the \"Logging\" icon.
    Verify the \"Format:\" under \"Log File\" is configured to \"W3C\".
    Select the \"Fields\" button.
    Under \"Custom Fields\", click the \"Add Field...\" button.
    For each field being added, give a name unique to what the field is
capturing.
    Click on the \"Source Type\" drop-down list and select \"Request Header\".
    Click on the \"Source\" drop-down list and select \"Connection\".
    Click \"OK\" to add.

    Click on the \"Source Type\" drop-down list and select \"Request Header\".
    Click on the \"Source\" drop-down list and select \"Warning\".
    Click \"OK\" to add.
    Click \"Apply\" under the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000099-WSR-000061'
  tag gid: 'V-218788'
  tag rid: 'SV-218788r561041_rule'
  tag stig_id: 'IIST-SV-000110'
  tag fix_id: 'F-20258r310840_fix'
  tag cci: ['V-100111', 'SV-109215', 'CCI-000134']
  tag nist: ['AU-3']

  ### One could also do get-iisSite to get the list of all configured sites and iterate ...

  # Get Log Format
  log_format = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logFormat"').stdout.strip
  describe 'IIS Logging format' do
    subject { log_format }
    it { should cmp 'W3C' }
  end

  # Get Custom Vars
  custom_field_configuration = command('Get-WebConfiguration -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields/*"').stdout.strip
  describe 'IIS Custom Fields logging configuration' do
    subject { custom_field_configuration }
    it { should match /sourceName\s+:\s+Connection\s+sourceType\s+:\s+RequestHeader/ }
    it { should match /sourceName\s+:\s+Warning\s+sourceType\s+:\s+RequestHeader/ }
    it { should match /sourceName\s+:\s+SERVER_NAME\s+sourceType\s+:\s+ServerVariable/ }
  end

end

