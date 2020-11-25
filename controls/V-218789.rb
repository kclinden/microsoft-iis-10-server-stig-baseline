# encoding: UTF-8

control 'V-218789' do
  title "The IIS 10.0 web server must produce log records containing sufficient
information to establish the identity of any user/subject or process associated
with an event."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Determining user accounts, processes running on behalf of the user, and
running process identifiers also enable a better understanding of the overall
event. User tool identification is also helpful to determine if events are
related to overall user access or specific client tools.

    Log record content that may be necessary to satisfy the requirement of this
control includes: time stamps, source and destination addresses, user/process
identifiers, event descriptions, success/fail indications, file names involved,
and access control or flow control rules invoked.
  "
  desc  'rationale', ''
  desc  'check', "
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under \"IIS\", double-click the \"Logging\" icon.
    Verify the \"Format:\" under \"Log File\" is configured to \"W3C\".
    Select the \"Fields\" button.
    Under \"Standard Fields\", verify \"User Agent\", \"User Name\", and
\"Referrer\" are selected.
    Under \"Custom Fields\", verify the following field has been configured:
    Request Header >> Authorization
    Response Header >> Content-Type
    If any of the above fields are not selected, this is a finding.
  "
  desc  'fix', "
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under \"IIS\", double-click the \"Logging\" icon.
    Verify the \"Format:\" under \"Log File\" is configured to \"W3C\".
    Select the \"Fields\" button.
    Under \"Standard Fields\", select \"User Agent\", \"User Name\", and
\"Referrer\".
    Under \"Custom Fields\", select the following fields:
    Click on the \"Source Type\" drop-down list and select \"Request Header\".
    Click on the \"Source\" drop-down list and select \"Authorization\".
    Click \"OK\" to add.

    Click on the \"Source\" drop-down list and select \"Content-Type\".
    Click on the \"Source Type\" drop-down list and select \"Response Header\".
    Click \"OK\" to add.
    Click \"OK\".
    Click \"Apply\" under the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000100-WSR-000064'
  tag gid: 'V-218789'
  tag rid: 'SV-218789r561041_rule'
  tag stig_id: 'IIST-SV-000111'
  tag fix_id: 'F-20259r505277_fix'
  tag cci: ['V-100113', 'SV-109217', 'CCI-001487']
  tag nist: ['AU-3']

  describe 'Manual review of web server is required.' do
    skip 'Manual review of web server is required'
  end

end

