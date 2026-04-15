"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 25 October 2018
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

QUERY_CACHE = {}
NS_A_CACHE = {}
ZONE_CACHE = {}
NS_LOOKUP_ACTIVE = set()


def _make_empty_response(target_name: dns.name.Name,
                         qtype: dns.rdata.Rdata) -> dns.message.Message:
    query = dns.message.make_query(target_name, qtype)
    return dns.message.make_response(query)


def _cache_key(target_name: dns.name.Name,
               qtype: dns.rdata.Rdata) -> tuple:
    return (str(target_name).lower(), int(qtype))


def _name_text(name) -> str:
    return str(name).lower()


def _best_start_servers(target_name: dns.name.Name) -> list:
    best_servers = None
    best_len = -1

    for zone_text in ZONE_CACHE:
        try:
            zone_name = dns.name.from_text(zone_text)
            if target_name.is_subdomain(zone_name):
                zone_len = len(zone_name.labels)
                if zone_len > best_len:
                    best_len = zone_len
                    best_servers = ZONE_CACHE[zone_text]
        except Exception:
            pass

    if best_servers is not None and len(best_servers) > 0:
        return best_servers[:]

    return list(ROOT_SERVERS)


def _send_query(server_ip: str,
                target_name: dns.name.Name,
                qtype: dns.rdata.Rdata):
    try:
        query = dns.message.make_query(target_name, qtype)
        query.flags &= ~0x0100
        return dns.query.udp(query, server_ip, 3)
    except Exception:
        return None


def _has_requested_answer(response: dns.message.Message,
                          qtype: dns.rdata.Rdata) -> bool:
    for rrset in response.answer:
        if rrset.rdtype == qtype:
            return True
    return False


def _first_cname_target(response: dns.message.Message):
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for rdata in rrset:
                return rdata.target
    return None


def _extract_a_ips_from_answer(response: dns.message.Message) -> list:
    ips = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rdata in rrset:
                ip = str(rdata)
                if ":" not in ip and ip not in ips:
                    ips.append(ip)
    return ips


def _extract_referral(response: dns.message.Message):
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            ns_names = []
            for rdata in rrset:
                if rdata.target not in ns_names:
                    ns_names.append(rdata.target)
            return rrset.name, ns_names
    return None, []


def _extract_glue_ipv4(response: dns.message.Message, ns_names: list) -> list:
    wanted = []
    for ns_name in ns_names:
        wanted.append(_name_text(ns_name))

    ips = []
    for rrset in response.additional:
        if rrset.rdtype != dns.rdatatype.A:
            continue
        if _name_text(rrset.name) not in wanted:
            continue
        for rdata in rrset:
            ip = str(rdata)
            if ":" not in ip and ip not in ips:
                ips.append(ip)
    return ips


def _store_zone_servers(zone_name: dns.name.Name, ips: list) -> None:
    zone_text = _name_text(zone_name)

    if zone_text not in ZONE_CACHE:
        ZONE_CACHE[zone_text] = []

    for ip in ips:
        if ip not in ZONE_CACHE[zone_text]:
            ZONE_CACHE[zone_text].append(ip)


def _combine_cname_and_final(original_name: dns.name.Name,
                             qtype: dns.rdata.Rdata,
                             cname_response: dns.message.Message,
                             final_response: dns.message.Message) -> dns.message.Message:
    combined = _make_empty_response(original_name, qtype)

    for rrset in cname_response.answer:
        combined.answer.append(rrset)

    for rrset in final_response.answer:
        duplicate = False
        for existing in combined.answer:
            if existing == rrset:
                duplicate = True
                break
        if not duplicate:
            combined.answer.append(rrset)

    return combined


def _resolve_ns_hostname_ipv4(ns_name: dns.name.Name) -> list:
    ns_text = _name_text(ns_name)

    if ns_text in NS_A_CACHE:
        return NS_A_CACHE[ns_text][:]

    if ns_text in NS_LOOKUP_ACTIVE:
        return []

    NS_LOOKUP_ACTIVE.add(ns_text)
    try:
        response = _iterative_lookup(ns_name, dns.rdatatype.A)
        ips = _extract_a_ips_from_answer(response)
        NS_A_CACHE[ns_text] = ips[:]
        return ips
    except Exception:
        NS_A_CACHE[ns_text] = []
        return []
    finally:
        if ns_text in NS_LOOKUP_ACTIVE:
            NS_LOOKUP_ACTIVE.remove(ns_text)


def _iterative_lookup(target_name: dns.name.Name,
                      qtype: dns.rdata.Rdata) -> dns.message.Message:
    key = _cache_key(target_name, qtype)
    if key in QUERY_CACHE:
        return QUERY_CACHE[key]

    servers = _best_start_servers(target_name)
    used_servers = set()
    last_response = None

    while len(servers) > 0:
        next_servers = []

        for server_ip in servers:
            if server_ip in used_servers:
                continue

            used_servers.add(server_ip)
            response = _send_query(server_ip, target_name, qtype)

            if response is None:
                continue

            last_response = response

            if response.rcode() == 3:
                QUERY_CACHE[key] = response
                return response

            if _has_requested_answer(response, qtype):
                QUERY_CACHE[key] = response
                return response

            cname_target = _first_cname_target(response)
            if cname_target is not None:
                if qtype == dns.rdatatype.CNAME:
                    QUERY_CACHE[key] = response
                    return response

                final_response = _iterative_lookup(cname_target, qtype)
                combined = _combine_cname_and_final(target_name, qtype,
                                                    response, final_response)
                QUERY_CACHE[key] = combined
                return combined

            zone_name, ns_names = _extract_referral(response)

            if zone_name is None:
                QUERY_CACHE[key] = response
                return response

            glue_ips = _extract_glue_ipv4(response, ns_names)
            if len(glue_ips) > 0:
                _store_zone_servers(zone_name, glue_ips)
                for ip in glue_ips:
                    if ip not in used_servers and ip not in next_servers:
                        next_servers.append(ip)
                continue

            # Unglued NS case: resolve NS hostnames using IPv4 A lookups only.
            resolved_ips = []
            for ns_name in ns_names:
                ns_ips = _resolve_ns_hostname_ipv4(ns_name)
                for ip in ns_ips:
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)

            if len(resolved_ips) > 0:
                _store_zone_servers(zone_name, resolved_ips)
                for ip in resolved_ips:
                    if ip not in used_servers and ip not in next_servers:
                        next_servers.append(ip)

        servers = next_servers

    if last_response is not None:
        QUERY_CACHE[key] = last_response
        return last_response

    return _make_empty_response(target_name, qtype)


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """
    try:
        return _iterative_lookup(target_name, qtype)
    except Exception:
        return _make_empty_response(target_name, qtype)


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))

if __name__ == "__main__":
    main()
