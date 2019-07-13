@load base/frameworks/notice/main.bro
@load base/frameworks/signatures/main.bro
@load policy/frameworks/dpd/detect-protocols.bro
@load policy/frameworks/software/vulnerable.bro
@load policy/misc/scan.bro
@load policy/protocols/ftp/detect-bruteforcing.bro
@load policy/protocols/smtp/blocklists.bro
@load policy/protocols/ssh/detect-bruteforcing.bro
@load policy/protocols/ssh/interesting-hostnames.bro
@load policy/protocols/ssl/expiring-certs.bro
@load policy/protocols/ssl/heartbleed.bro
@load policy/protocols/ssl/validate-certs.bro
@load policy/protocols/ssl/validate-ocsp.bro
@load policy/protocols/ssl/weak-keys.bro

@load exploit-kit.bro
@load http-sqli.bro
