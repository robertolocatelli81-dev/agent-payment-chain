"""What a tool writes of the endpoint URL it was given (SPEC 32.17): scheme://host[:port]. The path, the query and the
user part of a JSON-RPC URL are where the providers put the key (https://HOST/v2/KEY, ?api-key=KEY): they are never
written to an output, which is a file meant to be kept and published (as tools/anchor_msca.where and
sources/l1proof_20261024/fetch_l1proof.where already did)."""
import urllib.parse


def where(url):
    if not isinstance(url, str):
        return "?"
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or "?"
        return "%s://%s%s" % (u.scheme, "[%s]" % host if ":" in host else host, ":%d" % u.port if u.port else "")
    except (ValueError, AttributeError, TypeError):
        return "?"
