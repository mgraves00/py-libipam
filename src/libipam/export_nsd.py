#
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

class export_nsd:

    RR_FMT = {
            'SOA':  "{fqdn:<25} {ttl:<6} IN {rr_type} {fqdn} ( {email}. {serial} {refresh} {retry} {expire} {ncache} )",
            'A':      "{fqdn:<25} {ttl:<6} IN {rr_type} {value}",
            'AAAA':   "{fqdn:<25} {ttl:<6} IN {rr_type} {value}",
            'CNAME':  "{fqdn:<25} {ttl:<6} IN {rr_type} {value}.",
            'CAA':    "{fqdn:<25} {ttl:<6} IN {rr_type} {flag} {tag} {value}",
            'CERT':   "{fqdn:<25} {ttl:<6} IN {rr_type} {type} {tag} {algo} {value}",
            'DCHID':  "{fqdn:<25} {ttl:<6} IN {rr_type} {value}",
            'DNAME':  "{fqdn:<25} {ttl:<6} IN {rr_type} {value}",
            'DS':     "{fqdn:<25} {ttl:<6} IN {rr_type} {tag} {algo} {digest} ( {value} )",
            'HIP':    "{fqdn:<25} {ttl:<6} IN {rr_type} ( {algo} {hit} {key} {value} )",
            'LOC':    "{fqdn:<25} {ttl:<6} IN {rr_type} {lat} {long} {alt} {hor} {vert}",
            'MX':     "{fqdn:<25} {ttl:<6} IN {rr_type} {priority} {value}.",
            'NAPTR':  "{fqdn:<25} {ttl:<6} IN {rr_type} {order} \"{pref}\" \"{flags}\" \"{service\"} \"{regx}\" {value}",
            'NS':     "{fqdn:<25} {ttl:<6} IN {rr_type} {value}.",
            'PTR':    "{fqdn:<25} {ttl:<6} IN {rr_type} {value}",
            'SRV':    "{fqdn:<25} {ttl:<6} IN {rr_type} {priority} {weight} {port} {value}",
            'SSHFP':  "{fqdn:<25} {ttl:<6} IN {rr_type} {algo} {type} {value}",
            'TXT':    "{fqdn:<25} {ttl:<6} IN {rr_type} \"{value}\"",
            'TLSA':   "{fqdn:<25} {ttl:<6} IN {rr_type} {usage} {selector} {type} {value}",
            'XX':     "{fqdn:<25} {ttl:<6} IN {rr_type} {value}"
    }


    def __init__(self, *args, **kwargs):
        self.db = args[0]

    def process(self, *args, **kwargs):
        domain = kwargs.get('domain',None)
        if self.db == None or domain == None:
            raise Exception("missing arguments")

        file = []
        domain_record = self.db.find_domain(domain)
        resource_records = self.db.find_record("*."+domain)
        subdomain_record = self.db.find_domain("*."+domain)

        dom_r = domain_record[0]
#        dom_r = dom_r | { 'rr_type': "SOA"}
        dom_r = merge_dicts(dom_r, { 'rr_type': "SOA"})
        file.append(self._rr_print(dom_r))
        ns_recs = extract_records("NS", resource_records)
        mx_recs = extract_records("MX", resource_records)
        resource_records = clear_records(["NS", "MS"], resource_records)
        # add NS records
        for r in ns_recs:
            file.append(self._rr_print(r))
        # add MX records
        for r in resource_records:
            file.append(self._rr_print(r))

        # handle subdomains
        for sub in subdomain_record:
            save_ns=[]
            sub_rr = self.db.find_record("*."+sub['fqdn'])
            # only need to print the NS and A records for NS
            ns_recs = extract_records("NS", sub_rr)
            for r in ns_recs:
                file.append(self._rr_print(r))
                save_ns.append(r['value'])
            # now go back thru and look for the NS A records
            for i, r in enumerate(sub_rr):
                if r['fqdn'] in save_ns:
                    file.append(self._rr_print(r))
        return("\n".join(file))

    def _rr_print(self, kwargs):
        rr_type = kwargs['rr_type']
        opts = kwargs['options']
#        kwargs = kwargs | opts
        kwargs = merge_dicts(kwargs,opts)
        if kwargs.get('ttl') == None:
            kwargs['ttl'] = ""
        (name, domain) = self.db._splitfqdn(kwargs['fqdn'])
        if name == "@":
            kwargs['fqdn'] = domain+"."
        else:
            kwargs['fqdn'] = kwargs['fqdn']+"."
        if rr_type == "SOA":
            kwargs['serial'] = gen_serial()
        if self.RR_FMT[rr_type] != None:
            str=self.RR_FMT[rr_type].format(**kwargs)
        else:
            str=self.RR_FMT['XX'].format(**kwargs)
        return(str)

