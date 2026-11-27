"""Pure migration of Redut's sing-box 1.11 configurations to 1.14.

Unknown options are retained for `sing-box check`, never silently discarded.
The source configuration and backup files remain unchanged.
"""
import copy
import ipaddress
from urllib.parse import urlsplit


def migrate(config):
    """Return a migrated copy; reject legacy DNS options we cannot preserve."""
    result = copy.deepcopy(config)
    dns = result.get("dns", {})
    for server in dns.get("servers", []):
        if "address" not in server:
            continue
        if set(server) - {"tag", "address", "detour"}:
            raise ValueError("unsupported legacy DNS options; migrate explicitly")
        address = urlsplit(server["address"])
        if (address.scheme != "https" or not address.hostname or address.username
                or address.password or address.query or address.fragment):
            raise ValueError("unsupported legacy DNS address; migrate explicitly")
        ipaddress.ip_address(address.hostname)
        server.pop("address")
        server.update(type="https", server=address.hostname,
                      server_port=address.port or 443,
                      path=address.path or "/dns-query")
    dns.pop("independent_cache", None)

    route = result.setdefault("route", {})
    rules = route.setdefault("rules", [])
    prefix = []
    for inbound in result.get("inbounds", []):
        sniff = inbound.pop("sniff", False)
        timeout = inbound.pop("sniff_timeout", None)
        inbound.pop("sniff_override_destination", None)
        strategy = inbound.pop("domain_strategy", None)
        if sniff or (strategy and strategy != "as_is"):
            tag = inbound.get("tag")
            if not tag:
                raise ValueError("legacy inbound requires a tag for migration")
            if strategy and strategy != "as_is":
                prefix.append({"inbound": tag, "action": "resolve", "strategy": strategy})
            if sniff:
                rule = {"inbound": tag, "action": "sniff"}
                if timeout:
                    rule["timeout"] = timeout
                prefix.append(rule)

    dns_tags = {out.get("tag") for out in result.get("outbounds", [])
                if out.get("type") == "dns"}
    if dns_tags:
        if None in dns_tags or route.get("final") in dns_tags:
            raise ValueError("legacy DNS outbound has unsupported references")

        def migrate_rules(items):
            for rule in items:
                if rule.get("outbound") in dns_tags:
                    if rule.get("action", "route") != "route":
                        raise ValueError("legacy DNS rule has conflicting action")
                    rule.pop("outbound")
                    rule["action"] = "hijack-dns"
                migrate_rules(rule.get("rules", []))

        migrate_rules(rules)
        result["outbounds"] = [out for out in result["outbounds"]
                               if out.get("type") != "dns"]
    # An old installer may combine legacy inbounds with already migrated rules.
    # Repeated installation must not accumulate duplicate sniff/resolve actions.
    route["rules"] = [rule for rule in prefix if rule not in rules] + rules
    return result
