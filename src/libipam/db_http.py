###
### interface with ipamd server
###
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

import requests
import json

"""
    http interface for IPAMD

    Make connection to ipamd server.  pass commands from CLI to IAPMD sever and process it's responses

    [add|update|delete]_domain(fqdn, options={}, force=False)
        Accepts the :fqdn of the domain and the :options
        Does not check to make sure that required options are there.  Calling library should do that.
        If the ":force flag is true, on delete it will delete all records associated with domain too

    [add|udpate|delete]_record(fqdn, rr_type, value,  options={}, force=False)
        Accepts the :fqdn :rr_type :value of the record and the :options
        Does not check to make sure that required options are there.  Calling library should do that.
        If the ":force flag is true, on delete it will delete all records associated with record too

    find_[domain|record](fqdn, include_subs=False)
        Accepts the :name/:fqdn of the domain/record and searching for it.  If no :name/:fqdn is
        provided it does a wild card search.  Wild cards can also be added.
        If the :include_subs flag is set subdomains will also be returned

    find_network(network/bitmask)
        Accepts a :network/:mask and finds all records tha coorespond to the nework

    find_address(address)
        Accepts an :address and finds all records with that address

    NOTES:
        [add|update|delete]_* either return an exception or an empty list
        find_* will return a list of dict's with the following format
        find_[domain|record] only searches based upon name, not options
        find_[network|address] only searches based upon IP, not options
            [{ 'fqdn': value, 'tt_type': value, 'value': value, 'options': { dict of options } }]

"""
class db_http:
    API_URL="api"
    def __init__(self, server, port, key):
        self.server = server
        self.port = port
        self.api_key = key
        self.URL=f'http://{server}:{port}/{self.API_URL}'

    def close(self):
        pass

    ### Domains
    def find_domain(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "domain"]
        fqdn = args[0]
        if fqdn != None:
            path.append(fqdn)
        try:
            res = requests.get("/".join(path),headers=headers)
        except Exception as e:
            raise Exception(e)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}')
        r = json.loads(res.text)
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])
            

    def add_domain(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "domain"]
        if args[0] == None:
            raise Exception("name: not specified")
        data = { 'resouce': 'domain', 'fqdn': args[0], 'rr_type': 'SOA', 'value': None, 'options': kwargs.get('options',None) }
        jdata = json.dumps(data)
        try:
            res = requests.post("/".join(path),headers=headers,data=jdata)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}: {r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def update_domain(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "domain"]
        if args[0] == None:
            raise Exception("name: not specified")
        data = { 'resouce': 'domain', 'fqdn': args[0], 'rr_type': 'SOA', 'value': None, 'options': kwargs.get('options',None) }
        jdata = json.dumps(data)
        try:
            res = requests.put("/".join(path),headers=headers,data=jdata)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}: {r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def delete_domain(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "domain"]
        if args[0] == None:
            raise Exception("name: not specified")
        data = { 'resouce': 'domain', 'fqdn': args[0], 'rr_type': 'SOA', 'value': None, 'options': kwargs.get('options',None) }
        jdata = json.dumps(data)
        try:
            res = requests.delete("/".join(path),headers=headers,data=jdata)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}: {r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    ### records
    def find_record(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "record"]
        fqdn = args[0]
        if fqdn != None:
            path.append(fqdn)
        try:
            res = requests.get("/".join(path),headers=headers)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}: {r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def add_record(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "record"]
        if len(args) < 3:
            raise Exception("missing args")
        data = { 'resouce': 'record', 'fqdn': args[0], 'rr_type': args[1], 'value': args[2], 'options': kwargs.get('options',None) }
        jdata = json.dumps(data)
        try:
            res = requests.post("/".join(path),headers=headers,data=jdata)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}:{r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def update_record(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "record"]
        if len(args) < 3:
            raise Exception("missing args")
        data = { 'resouce': 'record', 'fqdn': args[0], 'rr_type': args[1], 'value': args[2], 'options': kwargs.get('options',None) }
        jdata = json.dumps(data)
        try:
            res = requests.put("/".join(path),headers=headers,data=jdata)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}:{r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def delete_record(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "record"]
        data = { 'resouce': 'record', 'fqdn': args[0], 'options': kwargs.get('options',None) }
        jdata = json.dumps(data)
        try:
            res = requests.delete("/".join(path),headers=headers,data=jdata)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}:{r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def find_network(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "network"]
        network = args[0]
        if network != None:
            path.append(network)
        try:
            res = requests.get("/".join(path),headers=headers)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}:{r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def find_address(self, *args, **kwargs):
        headers = {'Authorization': self.api_key}
        path = [self.URL, "address"]
        address = args[0]
        if address != None:
            path.append(address)
        try:
            res = requests.get("/".join(path),headers=headers)
        except Exception as e:
            raise Exception(e)
        r = json.loads(res.text)
        if res.status_code != 200:
            raise Exception(f'response code {res.status_code}:{r["msg"]}')
        if r['status'] == 'error':
            raise Exception(r['msg'])
        return(r['records'])

    def _splitfqdn(self, fqdn):
        if len(fqdn) == 0:
            return(None, None)
        sp = fqdn.split('.')
        return(sp[0],".".join(sp[1:]))

# do not allow ourselved to be alled directly
if __name__ == "__main__":
    raise Exception("cannot call directly")

