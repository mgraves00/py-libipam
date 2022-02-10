#
# Copyright 2022 Michael Graves <mgraves@brainfat.net>
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

from libipam.db_sqlite3 import db_sqlite3
from libipam.db_http import db_http
from libipam.export_bind import export_bind
from libipam.export_nsd import export_nsd
from libipam.export_unbound import export_unbound

class ipam:
    RR_OPTS = { 
        'SOA': { 'req': ['email','refresh','retry','expire','ncache'], 'opt':['ttl','serial'] },
        'A': { 'req': [], 'opt': ['ttl'] },
        'AFSDB': { 'req': ['subtype'], 'opt': ['ttl'] },
        'AAAA': { 'req': [], 'opt': ['ttl'] },
        'CAA': { 'req': ['flag','tag'], 'opt': ['ttl'] } , 
        'CERT': { 'req': ['type','tag','algo'], 'opt': ['ttl'] },
        'CNAME': { 'req': [], 'opt': ['ttl'] },
        'DCHID': { 'req': [], 'opt': ['ttl'] },
        'DNAME': { 'req': [], 'opt': ['ttl'] },
        'DS': { 'req': ['tag','algo','digest'], 'opt': ['ttl'] } , 
        'HIP': { 'req': ['algo','hit','key'], 'opt': ['ttl', 'rsv'] },
        'LOC': { 'req': ['ver','size','hor','vert','lat','long','alt'], 'opt': ['ttl'] },
        'MX': { 'req': ['priority'], 'opt': ['ttl'] } , 
        'NAPTR': { 'req': ['order','perf','flag','service','regx'], 'opt': ['ttl'] },
        'NS': { 'req': [], 'opt': ['ttl'] } , 
        'PTR': { 'req': [], 'opt': ['ttl'] },
        'RP': { 'req': ['mbox'], 'opt': ['ttl', 'mail'] } , 
        'SRV': { 'req': ['priority', 'weight', 'port'], 'opt': ['ttl'] } , 
        'SSHFP': { 'req': ['algo','type'], 'opt': ['ttl'] },
        'TXT': { 'req': [], 'opt': ['ttl'] },
        'TLSA': { 'req': ['usage', 'selector', 'type'], 'opt': ['ttl'] } , 
    }

    def __init__(self, *args, **kwargs):
        self.edriver = None
        dbtype = kwargs.get('database')
        if dbtype not in [ 'sqlite3', 'http' ]:
            raise Exception("unsupported database driver")
        if dbtype == "sqlite3":
            dbfile = kwargs.get('dbfile')
            self.db = db_sqlite3(dbfile)
        if dbtype == "http":
            server = kwargs.get('server')
            port = kwargs.get('port')
            key = kwargs.get('key')
            self.db = db_http(server,port,key)

    def find_domain(self, *args, **kwargs):
        return self.db.find_domain(*args, **kwargs)
    def add_domain(self, *args, **kwargs):
        return self.db.add_domain(*args, **kwargs)
    def update_domain(self, *args, **kwargs):
        return self.db.update_domain(*args, **kwargs)
    def delete_domain(self, *args, **kwargs):
        return self.db.delete_domain(*args, **kwargs)

    def find_record(self, *args, **kwargs):
        return self.db.find_record(*args, **kwargs)
    def find_network(self, *args, **kwargs):
        return self.db.find_network(*args, **kwargs)
    def find_address(self, *args, **kwargs):
        return self.db.find_address(*args, **kwargs)
    def add_record(self, *args, **kwargs):
        return self.db.add_record(*args, **kwargs)
    def update_record(self, *args, **kwargs):
        return self.db.update_record(*args, **kwargs)
    def delete_record(self, *args, **kwargs):
        return self.db.delete_record(*args, **kwargs)

    def check_options(self, *args, **kwargs):
        ok = []
        rr_type = args[0]
        given_opts = args[1]
        if rr_type not in self.RR_OPTS.keys():
            raise Exception("unknown rr_type")
        for key in self.RR_OPTS[rr_type]['req']:
            if key not in given_opts:
                return False
        return True

    def export(self, *args, **kwargs):
        e_type = kwargs.get('type', None);
        dom = kwargs.get('domain', None);
        if e_type == "bind":
            self.edriver = export_bind(self.db)
        elif e_type == "nsd":
            self.edriver = export_nsd(self.db)
        elif e_type == "unbound":
            self.edriver = export_unbound(self.db)
        return self.edriver.process(domain=dom)

    def unpack_options(self, options):
        # take the option DB format and create dict
        vals={}
        if type(options) != "str" or len(options) == 0:
            return(vals)
        for o in options.split(" "):
            (k,v) = o.split(":")
            vals[k]=v
        return(vals)

    def pack_options(self, options):
        # take a dict and make the option DB format
        s=[]
        if type(options) != "dict":
            return("")
        for k in options.keys():
            s.append("{}:{}".format(k,options[k]))
        return(" ".join(s))

