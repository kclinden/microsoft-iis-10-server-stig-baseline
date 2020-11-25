# encoding: UTF-8

control 'V-218787' do
  title "An IIS 10.0 web server behind a load balancer or proxy server must
produce log records containing the source client IP and destination
information."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct source (e.g., source IP), of the events is
important during forensic analysis. Correctly determining the source of events
will add information to the overall reconstruction of the loggable event. By
determining the source of the event correctly, analysis of the enterprise can
be undertaken to determine if events tied to the source occurred in other areas
within the enterprise.

    A web server behind a load balancer or proxy server, when not configured
correctly, will record the load balancer or proxy server as the source of every
loggable event. When looking at the information forensically, this information
is not helpful in the investigation of events. The web server must record with
each event the client source of the event.
  "
  desc  'rationale', ''
  desc  'check', "
    Interview the System Administrator to review the configuration of the IIS
10.0 architecture and determine if inbound web traffic is passed through a
proxy.

    If the IIS 10.0 web server is receiving inbound web traffic through a
proxy, the audit logs must be reviewed to determine if correct source
information is being passed through by the proxy server.

    Follow this procedure for web server and each website:

    Open the IIS 10.0 Manager.

    Click the IIS 10.0 web server name.

    Click the \"Logging\" icon.

    Click on \"View log files\" under the \"Actions\" pane.

    When the log file is displayed, review source IP information in log entries
and verify the entries do not reflect the IP address of the proxy server.

    If the website is not behind a load balancer or proxy server, this is Not
Applicable.

    If the log entries in the log file(s) reflect the IP address of the proxy
server as the source, this is a finding.

    If provisions have been made to log the client IP via another field (i.e.,
utilizing X-Forwarded-For), this is not a finding.
  "
  desc  'fix', "Access the proxy server through which inbound web traffic is
passed and configure settings to pass web traffic to the IIS 10.0 web server
transparently."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag gid: 'V-218787'
  tag rid: 'SV-218787r561041_rule'
  tag stig_id: 'IIST-SV-000109'
  tag fix_id: 'F-20257r310837_fix'
  tag cci: ['V-100109', 'SV-109213', 'CCI-000133']
  tag nist: ['AU-3']
end

