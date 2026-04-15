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
NS_CACHE = {}

def make_empty_response(target_name: dns.name.Name,
                        qtype: dns.rdata.Rdata) -> dns.message.Message:
    query = dns.message.make_query(target_name, qtype)
    return dns.message.make_response(query)


def copy_response(response: dns.message.Message) -> dns.message.Message:
    try:
        return dns.message.from_wire(response.to_wire())
    except Exception:
        return response


def cache_key(target_name: dns.name.Name,
              qtype: dns.rdata.Rdata) -> tuple:
    return (str(target_name).lower(), int(qtype))


def find_answer_type(response: dns.message.Message,
                     qtype: dns.rdata.Rdata) -> bool:
    for rrset in response.answer:
        if rrset.rdtype == qtype:
            return True
    return False


def find_cname_target(response: dns.message.Message):
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for rdata in rrset:
                return rdata.target
    return None


def get_ns_names(response: dns.message.Message) -> list:
    ns_names = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rdata in rrset:
                if rdata.target not in ns_names:
                    ns_names.append(rdata.target)
    return ns_names


def get_glue_ips(response: dns.message.Message, ns_names: list) -> list:
    wanted = []
    for ns_name in ns_names:
        wanted.append(str(ns_name).lower())

    ips = []
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            rr_name = str(rrset.name).lower()
            if rr_name in wanted:
                for rdata in rrset:
                    ip = str(rdata)
                    if ":" not in ip and ip not in ips:
                        ips.append(ip)
    return ips


def resolve_ns_name(ns_name: dns.name.Name) -> list:
    ns_text = str(ns_name).lower()

    if ns_text in NS_CACHE:
        return NS_CACHE[ns_text][:]

    response = iterative_lookup(ns_name, dns.rdatatype.A)
    ips = []

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rdata in rrset:
                ip = str(rdata)
                if ":" not in ip and ip not in ips:
                    ips.append(ip)

    NS_CACHE[ns_text] = ips[:]
    return ips


def get_next_servers(response: dns.message.Message) -> list:
    ns_names = get_ns_names(response)
    if not ns_names:
        return []

    glue_ips = get_glue_ips(response, ns_names)
    if glue_ips:
        return glue_ips

    next_servers = []
    for ns_name in ns_names:
        ips = resolve_ns_name(ns_name)
        for ip in ips:
            if ip not in next_servers:
                next_servers.append(ip)

    return next_servers


def iterative_lookup(target_name: dns.name.Name,
                     qtype: dns.rdata.Rdata) -> dns.message.Message:
    key = cache_key(target_name, qtype)
    if key in QUERY_CACHE:
        return copy_response(QUERY_CACHE[key])

    servers = list(ROOT_SERVERS)
    used_servers = set()
    last_response = None

    while len(servers) > 0:
        next_servers = []

        for server in servers:
            if server in used_servers:
                continue
            used_servers.add(server)

            try:
                query = dns.message.make_query(target_name, qtype)
                query.flags &= ~0x0100
                response = dns.query.udp(query, server, 3)
            except Exception:
                continue

            last_response = response

            if find_answer_type(response, qtype):
                QUERY_CACHE[key] = copy_response(response)
                return copy_response(response)

            cname_target = find_cname_target(response)
            if cname_target is not None:
                if qtype == dns.rdatatype.CNAME:
                    QUERY_CACHE[key] = copy_response(response)
                    return copy_response(response)

                cname_response = iterative_lookup(cname_target, qtype)
                final_response = make_empty_response(target_name, qtype)

                for rrset in response.answer:
                    final_response.answer.append(rrset)

                for rrset in cname_response.answer:
                    final_response.answer.append(rrset)

                QUERY_CACHE[key] = copy_response(final_response)
                return final_response

            referral_servers = get_next_servers(response)
            for ip in referral_servers:
                if ip not in used_servers and ip not in next_servers:
                    next_servers.append(ip)

        servers = next_servers

    if last_response is not None:
        QUERY_CACHE[key] = copy_response(last_response)
        return copy_response(last_response)

    return make_empty_response(target_name, qtype)





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
        return iterative_lookup(target_name, qtype)
    except Exception:
        return make_empty_response(target_name, qtype)


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    printed = False
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))
            printed = True

    if not printed:
        print("no records found")


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
        try:
            print_results(collect_results(a_domain_name))
        except Exception:
            print("no records found")

if __name__ == "__main__":
    main()
