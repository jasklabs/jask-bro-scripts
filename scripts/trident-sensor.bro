@load base/init-bare.bro

@load misc/loaded-scripts
@load tuning/defaults
@load misc/capture-loss
@load misc/stats
@load misc/scan
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames

#JASK custom
@load file-hash.bro
@load file-carving.bro
@load smtp-quotes-in-header.bro
@load http-header-values.bro
@load http-form-data.bro
@load osdetect.bro
@load logrotate.bro
@load filter.bro
@load notices.bro
@load ja3.bro
redef FileExtract::prefix = "/opt/trident/sensor/output/extract_files/";
@load policy/misc/capture-loss.bro
redef CaptureLoss::too_much_loss = 0.05;

@load policy/tuning/json-logs.bro
@load policy/protocols/dns/detect-external-names.bro
@load policy/protocols/http/detect-sqli.bro
@load policy/protocols/http/detect-webapps.bro
@load policy/protocols/http/software.bro
@load policy/protocols/http/software-browser-plugins.bro
@load policy/protocols/http/var-extraction-cookies.bro
@load policy/protocols/http/var-extraction-uri.bro

@load policy/protocols/smb
@load policy/protocols/smb/smb1-main.bro
@load policy/protocols/smb/smb2-main.bro
@load smb_cmd.bro

@load base/protocols/rfb
@load policy/protocols/conn/vlan-logging.bro
@load policy/protocols/conn/mac-logging.bro

@unload base/protocols/syslog

@load base/utils/site
@load base/utils/active-http
@load base/utils/addrs
@load base/utils/conn-ids
@load base/utils/dir
@load base/utils/directions-and-hosts
@load base/utils/exec
@load base/utils/files
@load base/utils/numbers
@load base/utils/paths
@load base/utils/patterns
@load base/utils/queue
@load base/utils/strings
@load base/utils/thresholds
@load base/utils/time
@load base/utils/urls

@load base/frameworks/notice
@load base/frameworks/analyzer
@load base/frameworks/dpd
@load base/frameworks/signatures
@load base/frameworks/packet-filter
@load base/frameworks/software
@load base/frameworks/communication
@load base/frameworks/control
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/reporter
@load base/frameworks/sumstats
@load base/frameworks/tunnels

@load base/protocols/conn
@load base/protocols/dhcp
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh

@load base/files/pe
@load base/files/hash
@load base/files/extract
@load base/files/unified2
@load base/files/x509

@load base/misc/find-checksum-offloading
@load base/misc/find-filtered-trace
