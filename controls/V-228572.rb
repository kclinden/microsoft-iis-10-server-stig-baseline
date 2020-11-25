# encoding: UTF-8

control 'V-228572' do
  title "An IIS Server configured to be a SMTP relay must require
authentication."
  desc  "Anonymous SMTP relays are strictly prohibited. An anonymous SMTP relay
can be a vector for many types of malicious activity not limited to server
exploitation for the sending of SPAM mail, access to emails, phishing, DoS
attacks, etc. Enabling TLS, authentication, and strictly assigning IP addresses
that can communicate with the relay greatly reduce the risk of the
implementation."
  desc  'rationale', ''
  desc  'check', "
    Interview the System Administrator about the role of the IIS 10.0 web
server.

    If the IIS 10.0 web server is running SMTP relay services, have the SA
provide supporting documentation on how the server is hardened. A DoD-issued
certificate, and specific allowed IP address should be configured.

    If the IIS web server is not running SMTP relay services, this is Not
Applicable.

    If the IIS web server running SMTP relay services without TLS enabled, this
is a finding.

    If the IIS web server running SMTP relay services is not configured to only
allow a specific IP address, from the same network as the relay, this is a
finding.
  "
  desc  'fix', "Configure the relay server with a specific allowed IP address,
from the same network as the relay, and implement TLS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag gid: 'V-228572'
  tag rid: 'SV-228572r561041_rule'
  tag stig_id: 'IIST-SV-000160'
  tag fix_id: 'F-30783r505289_fix'
  tag cci: ['SV-111857', 'V-102895', 'CCI-000381']
  tag nist: ['CM-7 a']

  describe 'This test currently has no automated tests, you must check manually' do
    skip 'This check must be preformed manually'
  end

end

