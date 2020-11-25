# encoding: UTF-8

control 'V-218799' do
  title "The IIS 10.0 web server must have Web Distributed Authoring and
Versioning (WebDAV) disabled."
  desc  "A web server can be installed with functionality that by its nature is
not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP
protocol which, when developed, was meant to allow users to create, change, and
move documents on a server, typically a web server or web share. Allowing this
functionality, development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Review the features listed under the “IIS\" section.

    If the \"WebDAV Authoring Rules\" icon exists, this is a finding.
  "
  desc  'fix', "
    Access Server Manager on the IIS 10.0 web server.

    Click the IIS 10.0 web server name.

    Click on \"Manage\".

    Select \"Add Roles and Features\".

    Click \"Next\" in the \"Before you begin\" dialog box.

    Select \"Role-based or feature-based installation\" on the \"Installation
Type\" dialog box and click \"Next\".

    Select the IIS 10.0 web server in the \"Server Selection\" dialog box.

    From the \"Windows Features\" dialog box, navigate to \"World Wide Web
Services\" >> \"Common HTTP Features\".

    De-select \"WebDAV Publishing\", and click \"Next\" to complete removing
the WebDAV Publishing feature from the IIS 10.0 web server.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-218799'
  tag rid: 'SV-218799r561041_rule'
  tag stig_id: 'IIST-SV-000125'
  tag fix_id: 'F-20269r310873_fix'
  tag cci: ['SV-109237', 'V-100133', 'CCI-000381']
  tag nist: ['CM-7 a']

  describe windows_feature('Web-DAV-Publishing') do
    it { should_not be_installed }
  end

end

