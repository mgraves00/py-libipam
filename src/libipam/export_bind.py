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

import time
from libipam.utils import *

class export_bind:

    RR_FMT = {
            'SOA':    "@          {ttl:<6} IN {rr_type} {fqdn}. ( {email}. {serial} {refresh} {retry} {expire} {ncache} )",
            'A':      "{fqdn:<10} {ttl:<6} IN {rr_type} {value}",
            'AAAA':   "{fqdn:<10} {ttl:<6} IN {rr_type} {value}",
            'CNAME':  "{fqdn:<10} {ttl:<6} IN {rr_type} {value}.",
            'CAA':    "{fqdn:<10} {ttl:<6} IN {rr_type} {flag} {tag} {value}",
            'CERT':   "{fqdn:<10} {ttl:<6} IN {rr_type} {type} {tag} {algo} {value}",
            'DCHID':  "{fqdn:<10} {ttl:<6} IN {rr_type} {value}",
            'DNAME':  "{fqdn:<10} {ttl:<6} IN {rr_type} {value}",
            'DS':     "{fqdn:<10} {ttl:<6} IN {rr_type} {tag} {algo} {digest} ( {value} )",
            'HIP':    "{fqdn:<10} {ttl:<6} IN {rr_type} ( {algo} {hit} {key} {value} )",
            'LOC':    "{fqdn:<10} {ttl:<6} IN {rr_type} {lat} {long} {alt} {hor} {vert}",
            'MX':     "{fqdn:<10} {ttl:<6} IN {rr_type} {priority} {value}.",
            'NAPTR':  "{fqdn:<10} {ttl:<6} IN {rr_type} {order} \"{pref}\" \"{flags}\" \"{service\"} \"{regx}\" {value}",
            'NS':     "{fqdn:<10} {ttl:<6} IN {rr_type} {value}.",
            'PTR':    "{fqdn:<10} {ttl:<6} IN {rr_type} {value}",
            'SRV':    "{fqdn:<10} {ttl:<6} IN {rr_type} {priority} {weight} {port} {value}",
            'SSHFP':  "{fqdn:<10} {ttl:<6} IN {rr_type} {algo} {type} {value}",
            'TXT':    "{fqdn:<10} {ttl:<6} IN {rr_type} \"{value}\"",
            'TLSA':   "{fqdn:<10} {ttl:<6} IN {rr_type} {usage} {selector} {type} {value}",
            'XX':     "{fqdn:<10} {ttl:<6} IN {rr_type} {value}"
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

        file.append(f'$ORIGIN {domain}.')
        dom_r = domain_record[0]
#        dom_r = dom_r | { 'rr_type': "SOA"}
        dom_r = merge_dicts(dom_r, { 'rr_type': "SOA"})
        file.append(self._rr_print(dom_r))
        ns_recs = self._extract_records("NS", resource_records)
        mx_recs = self._extract_records("MX", resource_records)
        resource_records = self._clear_records(["NS", "MS"], resource_records)
        # add NS records
        for r in ns_recs:
            file.append(self._rr_print(r))
        # add MX records
        for r in resource_records:
            file.append(self._rr_print(r))

        # handle subdomains
        for sub in subdomain_record:
            file.append(f'$ORIGIN {sub["fqdn"]}.')
            save_ns=[]
            sub_rr = self.db.find_record("*."+sub['fqdn'])
            # only need to print the NS and A records for NS
            ns_recs = self._extract_records("NS", sub_rr)
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
        if rr_type == "SOA":
            kwargs['serial'] = self._gen_serial()
#        if rr_type != "SOA":
#            (name, domain) = self.db._splitfqdn(kwargs['fqdn'])
#            kwargs['name'] = name
#            kwargs['domain'] = domain
        if self.RR_FMT[rr_type] != None:
            str=self.RR_FMT[rr_type].format(**kwargs)
        else:
            str=self.RR_FMT['XX'].format(**kwargs)
        return(str)

    def _rr_sorted(self, a, b):
        # sort by name, @ first, then rr_type
        if a['fqdn'] < b['fqdn']:
            return -1
        elif a['fqdn'] > b['fqdn']:
            return 1
        else:
            if a['rr_type'] < b['rr_type']:
                return -1
            elif a['rr_type'] > b['rr_type']:
                return 1
            else:
                return 0

    def _extract_records(self, rr_type,  rrl):
        ret=[]
        for i, r in enumerate(rrl):
            if r['rr_type'] == rr_type:
                ret.append(r)
        return(ret)

    def _clear_records(self, rec_l, rrl):
        ret=[]
        for i, r in enumerate(rrl):
            if r['rr_type'] not in rec_l:
                ret.append(r)
        return(ret)

    def _gen_serial(self):
        return int(time.time())

