"""Amendment 0.11.4 (SPEC section 18): resource URLs and hosts outside ASCII. A host is compared as its IDNA A-label
form (RFC 3490 ToASCII with the stdlib codec, Nameprep RFC 3491, Punycode RFC 3492); an IRI is compared with a URI
after the mapping of RFC 3987 3.1 (host to A-labels, every other non-ASCII character as %-escaped UTF-8). Where IDNA
2003 (the stdlib) and IDNA 2008 / UTS 46 (what browsers apply) can give different A-labels for one input, the host is
refused as ambiguous instead of compared: the deviation characters U+00DF, U+03C2, U+200C, U+200D (UTS 46 section 6.1:
"Deviations")."""
import encodings.idna
import re
from urllib.parse import urlsplit, urlunsplit

DEVIATIONS = {"\u00df", "\u03c2", "\u200c", "\u200d"}
LDH = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class NotComparable(ValueError):
    pass


def host_ascii(host):
    """The lower-case A-label form of a host name, or NotComparable(reason)."""
    if not isinstance(host, str) or not host or len(host) > 1024:
        raise NotComparable("host_empty_or_too_long")
    if host.startswith("[") or re.fullmatch(r"[0-9.]+", host):      # IP literals are compared as written
        return host.lower()
    if any(c in DEVIATIONS for c in host):
        raise NotComparable("idna_deviation_character")
    labels = host.rstrip(".").split(".")
    out = []
    for lab in labels:
        if not lab:
            raise NotComparable("empty_label")
        if lab.isascii():
            a = lab.lower()
        else:
            try:
                a = encodings.idna.ToASCII(lab).decode("ascii").lower()
            except UnicodeError:
                raise NotComparable("label_not_idna")
        if not LDH.match(a):
            raise NotComparable("label_not_ldh")
        if a.startswith("xn--"):
            try:                                    # an A-label must decode and re-encode to itself
                if encodings.idna.ToASCII(encodings.idna.ToUnicode(a)).decode("ascii").lower() != a:
                    raise NotComparable("a_label_not_canonical")
            except UnicodeError:
                raise NotComparable("a_label_not_canonical")
        out.append(a)
    return ".".join(out)


def _pct(s):
    return "".join(c if c.isascii() else "".join("%%%02X" % b for b in c.encode("utf-8")) for c in s)


def iri_to_uri(iri):
    """RFC 3987 3.1 for http(s) IRIs: the URI, or NotComparable(reason)."""
    try:
        u = urlsplit(iri)
        host, port = u.hostname, u.port
    except ValueError:
        raise NotComparable("not_a_url")
    if u.scheme.lower() not in ("http", "https") or not host or "@" in u.netloc:
        raise NotComparable("not_an_http_url_with_a_host")
    netloc = host_ascii(host) + (":%d" % port if port is not None else "")
    return urlunsplit((u.scheme.lower(), netloc, _pct(u.path), _pct(u.query), _pct(u.fragment)))


def origin(url):
    """scheme://a-label-host[:port] of an http(s) URL, or None when it has none or is not comparable."""
    try:
        u = urlsplit(url)
        if u.scheme.lower() not in ("http", "https") or not u.hostname or "@" in u.netloc:
            return None
        return "%s://%s%s" % (u.scheme.lower(), host_ascii(u.hostname), ":%d" % u.port if u.port is not None else "")
    except (ValueError, NotComparable):
        return None
