#
# Copyright 2026 Michael Graves <mg@brainfat.net>
# Copyright 2025 Michael Graves <mg@brainfat.net>
# Copyright 2022 Michael Graves <mg@brainfat.net>
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
# 
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
# 
#     3. Neither the name of the copyright holder nor the names of its
#        contributors may be used to endorse or promote products derived from
#        this software without specific prior written permission.
# 
#     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#     "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
#     TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#     A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#     HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#     LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
#     USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#     ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#     OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
#     OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#     SUCH DAMAGE.

from libipam.utils import *

class export_bind:

    RR_FMT = {
            'SOA':    "@          {ttl:<6} IN {rr_type} {mname}. {email}. ( {serial} {refresh} {retry} {expire} {ncache} )",
            'A':      "{name:<10} {ttl:<6} IN {rr_type} {value}",
            'AAAA':   "{name:<10} {ttl:<6} IN {rr_type} {value}",
            'CNAME':  "{name:<10} {ttl:<6} IN {rr_type} {value}.",
            'CAA':    "{name:<10} {ttl:<6} IN {rr_type} {flag} {tag} {value}",
            'CERT':   "{name:<10} {ttl:<6} IN {rr_type} {type} {tag} {algo} {value}",
            'DCHID':  "{name:<10} {ttl:<6} IN {rr_type} {value}",
            'DNAME':  "{name:<10} {ttl:<6} IN {rr_type} {value}.",
            'DS':     "{name:<10} {ttl:<6} IN {rr_type} {tag} {algo} {digest} ( {value} )",
            'HIP':    "{name:<10} {ttl:<6} IN {rr_type} ( {algo} {hit} {key} {value} )",
            'LOC':    "{name:<10} {ttl:<6} IN {rr_type} {lat} {long} {alt} {hor} {vert}",
            'MX':     "{name:<10} {ttl:<6} IN {rr_type} {priority} {value}.",
            'NAPTR':  "{name:<10} {ttl:<6} IN {rr_type} {order} \"{pref}\" \"{flags}\" \"{service\"} \"{regx}\" {value}",
            'NS':     "{name:<10} {ttl:<6} IN {rr_type} {value}.",
            'PTR':    "{revaddr:<10} {ttl:<6} IN {rr_type} {fqdn}",
            'PTR6':   "{revaddr:<10} {ttl:<6} IN {rr_type} {fqdn}",
            'SRV':    "{name:<10} {ttl:<6} IN {rr_type} {priority} {weight} {port} {value}.",
            'SSHFP':  "{name:<10} {ttl:<6} IN {rr_type} {algo} {type} {value}",
            'TXT':    "{name:<10} {ttl:<6} IN {rr_type} \"{value}\"",
            'TLSA':   "{name:<10} {ttl:<6} IN {rr_type} {usage} {selector} {type} {value}",
            'XX':     "{name:<10} {ttl:<6} IN {rr_type} {value}"
    }

    def __init__(self, *args, **kwargs):
        self.db = args[0]

    def process(self, *args, **kwargs):
        d = kwargs.get('domain', None)
        n = kwargs.get('network', None)
        if d != None:
            return self.process_domain(*args, **kwargs)
        if n != None:
            return self.process_network(*args, **kwargs)
        return None

    def process_network(self, *args, **kwargs):
        network = kwargs.get('network',None)
        if self.db == None or network == None:
            raise Exception("missing arguments")
        file = []
        network = validate_network(network)
        if network == None:
            raise Exception("invalid network")
        revdom = net_to_rev(network)
        # SOA record for reverse zone
        revdom_SOA = self.db.find_domain(revdom)
        if len(revdom_SOA) == 0:
            raise Exception("network not found")
        # NS records for reverse zone
        resource_records = self.db.find_record("*."+revdom)
        ns_recs = extract_records("NS", resource_records)
        # remaining records
        network_records = self.db.find_network(network)
        file.append(f'$ORIGIN {revdom}.')
        # add NS records
        for r in ns_recs:
            (name,domain) = splitfqdn(r['fqdn'])
            r['name'] = name
            file.append(self._rr_print(**r))
        for r in network_records:
            r['revaddr'] = rev_addr(r['value'])
            r['revaddr'] = stripdomain(r['revaddr'],revdom)
            if r['revaddr'] != None:
                file.append(self._revr_print(**r))
        return("\n".join(file))

    def process_domain(self, *args, **kwargs):
        domain = kwargs.get('domain',None)
        if self.db == None or domain == None:
            raise Exception("missing arguments")
        file = []
        domain_record = self.db.find_domain(domain)
        resource_records = self.db.find_record("*."+domain)
        subdomain_record = self.db.find_domain("*."+domain, include_subs=True)
        file.append(f'$ORIGIN {domain}.')
        dom_r = domain_record[0]
        dom_r = merge_dicts(dom_r, { 'rr_type': "SOA"})
        file.append(self._rr_print(**dom_r))
        ns_recs = extract_records("NS", resource_records)
        mx_recs = extract_records("MX", resource_records)
        resource_records = clear_records(["NS", "MX"], resource_records)
        # add NS records
        for r in ns_recs:
            (name,domain) = splitfqdn(r['fqdn'])
            r['name'] = name
            file.append(self._rr_print(**r))
        # add MX records
        for r in mx_recs:
            (name,domain) = splitfqdn(r['fqdn'])
            r['name'] = name
            file.append(self._rr_print(**r))
        # handle subdomains
        for sub in subdomain_record:
            file.append(f'$ORIGIN {sub["fqdn"]}.')
            save_ns=[]
            sub_rr = self.db.find_record("*."+sub['fqdn'])
            # only need to print the NS and A records for NS
            ns_recs = extract_records("NS", sub_rr)
            for r in ns_recs:
                (name,domain) = splitfqdn(r['fqdn'])
                r['name'] = name
                file.append(self._rr_print(**r))
                save_ns.append(r['value'])
            # now go back thru and look for the NS A records
            for i, r in enumerate(sub_rr):
                if r['fqdn'] in save_ns:
                    (name,domain) = splitfqdn(r['fqdn'])
                    r['name'] = name
                    file.append(self._rr_print(**r))
       # now output resoure records
        for r in resource_records:
            (name,domain) = splitfqdn(r['fqdn'])
            r['name'] = name
            file.append(self._rr_print(**r))

        return("\n".join(file))

    def _rr_print(self, **kwargs):
        return rr_print(self.RR_FMT, **kwargs)

    def _revr_print(self, **kwargs):
        return revr_print(self.RR_FMT, **kwargs)
