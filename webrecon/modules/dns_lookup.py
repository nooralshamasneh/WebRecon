"""DNS records for the target domain."""
from .. import dnsutil

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "CAA"]


def get_dns_records(domain):
    return {rtype: values for rtype in RECORD_TYPES if (values := dnsutil.lookup(domain, rtype))}
