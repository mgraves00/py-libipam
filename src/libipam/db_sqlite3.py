###
### interface with ipam.db
###
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

import sqlite3
import ipaddress
import os
from libipam.utils import *

"""
    database interface for IPAM DB

    Initializing the class will look for the database.  If it is not found, it will create it and
    initialize the schema.

    [add|update|delete]_domain(fqdn, options={}, force=False)
        Accepts the :name of the domain and the :options
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
        Accepts a network/mask and finds all records tha coorespond to the nework

    find_address(address)
        Accepts an address and finds all records with that address

    NOTES:
        [add|update|delete]_* either return an exception or an empty list
        find_* will return a list of dict's with the following format
        find_[domain|record] only searches based upon name, not options
        find_[network|address] only searches based upon IP, not options
            [{ 'fqdn': value, 'tt_type': value, 'value': value, 'options': { dict of options } }]

"""
class db_sqlite3:
    SCHEMA_FILE="sqlite3.schema"
    def __init__(self, dbfile):
        self.dbfile = dbfile
        self.con = None
        self.con = sqlite3.connect(dbfile, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self.con.row_factory = sqlite3.Row
        self._dbinit()

    def _dbinit(self):
        cur = self.con.cursor()
        try:
            # check for schema
            cur.execute("SELECT 1 FROM domains;",())
            cur.close()
        except:
            # schema not there... add it
            fullschema = os.path.dirname(os.path.abspath(__file__))+"/"+self.SCHEMA_FILE
            schema=""
            f = open(fullschema, 'r')
            for l in f:
                schema=schema+l
            f.close()
            cur.executescript(schema);
            cur.close()
            self.con.commit()

    def close(self):
        if self.con != None:
            self.con.close()
            self.con = None

    ### Domains
    def find_domain(self, *args, **kwargs):
        name = args[0]
        include_subs = kwargs.get('include_subs',False)
        sql = 'SELECT * FROM domains'
        values={}
        if name != None:
            if name.find('*') == -1:
                sql=sql+" WHERE name = :name"
            else:
                name = name.replace('*','%')
                sql=sql+" WHERE name LIKE :name"
            values['name'] = name
            if include_subs == True:
                sql=sql+" OR name LIKE :subname"
                values['subname'] = "%."+name
        sql=sql+" ORDER BY name ASC;"
        result = self._query(sql, values)
        ret = []
        for res in result:
            if 'options' in res:
                options = self._unpack_options(res['options'])
            ret.append({ 'id': res['id'], 'fqdn': res['name'], 'rr_type': 'SOA', 'serial': res['serial'], 'value': None, 'options': options })
        return(ret)

    def add_domain(self, *args, **kwargs):
        sql=""
        name = args[0]
        if len(name) <= 0:
            raise Exception("name: not specified")
        r = self.find_domain(name)
        if len(r) > 0: # domain already exists
            raise Exception("domain already exists")
        options = kwargs.get('options',None)
        # :serial is passed as an options, but it isn't really
        # extract and remove from options or set to None
        if options != None:
            serial = options.get('serial',None)
            try:
                del options['serial']
            except:
                pass
        else:
            serial = None
        options = self._pack_options(options)
        if serial == None:
            sql = 'INSERT INTO domains (name,options) VALUES (:name,:options);'
        else:
            sql = 'INSERT INTO domains (name,serial,options) VALUES (:name,:serial,:options);'
        values = { 'name': name, 'serial': serial, 'options': options }
        # will always return an empty array
        return self._query(sql, values)

    def update_domain(self, *args, **kwargs):
        name = args[0]
        options = kwargs.get('options',None)
        if options != None:
            od = self._unpack_options(options)
            serial = od.get('serial',None)
            try:
                del od['serial']
            except:
                pass
            options = self._pack_options(od)
        else:
            serial = None
        rid=None
        if len(name) <= 0:
            raise Exception("name: not specified")
        r = self.find_domain(name)
        if len(r) == 0:
            raise Exception("domain does not exist")
        rid = r[0]['id']
        if serial == None:
            sql = 'UPDATE domains SET name=:name, options=:opts WHERE id=:id;'
        else:
            sql = 'UPDATE domains SET name=:name, serial=:serial, options=:opts WHERE id=:id;'
        # will always return an empty array
        return self._query(sql, {'name': name, 'serial': serial, 'opts': options, 'id': rid});

    def delete_domain(self, *args, **kwargs):
        sql = 'DELETE FROM domains WHERE id=:id;'
        name = args[0]
        if len(name) == 0:
            raise Exception("name: not specified")
        force = kwargs.get('force',False)
        r = self.find_domain(name)
        if len(r) == 0:     # domain not found
            raise Exception("domain does not exist")
        domain_id = r[0]['id']
        if force == False:
            sql1 = 'SELECT count(*) AS cnt FROM records WHERE domain_id=:domain_id;'
            r = self._query(sql1, {'domain_id': domain_id})
            if r[0]['cnt'] > 0:  # have records attached to the domain
                raise Exception("domain is not empty. use -f to clear")
        # will always return an empty array
        return self._query(sql, {'id': domain_id})

    ### records
    def find_record(self, *args, **kwargs):
        fqdn = args[0]
        include_subs = kwargs.get('include_subs',False)
        values={}
        sql = "SELECT * FROM fqdn_records"
        if (fqdn != None):
            sql=sql+" WHERE"
            (name, domain) = self._splitfqdn(fqdn)
            if name == None or domain == None:
                raise Exception("missing required argument")
            if include_subs == False:
                res = self.find_domain(domain)
                if len(res) == 0:
                    raise Exception("domain not found")
                values['domain_id'] = res[0]['id']
                sql=sql+" domain_id = :domain_id AND"
            if fqdn.find('*') == -1:
                sql=sql+" fqdn = :name"
            else:
                fqdn = fqdn.replace('*','%')
                sql=sql+" fqdn LIKE :name"
            values["name"] = fqdn
        sql=sql+" ORDER BY fqdn ASC;"
        result = self._query(sql, values)
        ret = []
        for res in result:
            if 'options' in res:
                options = self._unpack_options(res['options'])
            ret.append({ 'id': res['id'], 'fqdn': res['fqdn'], 'rr_type': res['rr_type'], 'value': res['value'], 'options': options })
        return(ret)

    def add_record(self, *args, **kwargs):
        fqdn = args[0]
        rr_type = args[1]
        value = args[2]
        if fqdn == None or rr_type == None or value == None:
            raise Exception("missing required argument")
        (name, domain) = self._splitfqdn(fqdn)
        if name == None or domain == None:
            raise Exception("required field not specified")
        recs = self.find_record(fqdn)
        if len(recs) > 0:      # record migh already exists... check all returned vals
            for r in recs:
                # we already know that the fqdn matches... check the type and value
                if r['rr_type'] == rr_type.upper() and r['value'] == value.lower(): # otherwise it might be a different type of record
                    raise Exception("host already exists")

        options = kwargs.get('options',None)
        if options != None:
            options = self._pack_options(options)
        else:
            options = ""
        sql = 'INSERT INTO records ({}) VALUES ({});'
        rr_type=rr_type.upper()
        values={'name':name, 'rr_type': rr_type}
        try:
            r = self.find_domain(domain)
            if len(r) == 0:
                raise Exception("domain not found")
            if len(r) > 1:
                raise Exception("too many records")
            domain_id = r[0]['id']
            values['domain_id'] = r[0]['id']
        except Exception as e:
            raise Exception(e)
        vals = self._fixup_values(rr_type, value)
#        values = values | vals
        values = merge_dicts(values,vals)
        values['options'] = options
        sql=sql.format(','.join(values.keys()), ",".join(list(map(lambda a: ":"+a, values.keys()))))
        return self._query(sql, values)

    def update_record(self, *args, **kwargs):
        fqdn = args[0]
        rr_type = args[1].upper()
        value = args[2]
        if fqdn == None:
            raise Exception("required field not specified")
        recs = self.find_record(fqdn)
        rid = None
        found = False
        if len(recs) == 0:  # record not found
            raise Exception("could not find record")
        else:
            if 'id' not in kwargs:
                raise Exception("id missing")
            rid = kwargs['id']
            for r in recs:
                # we already know that the fqdn matches... check the type and id
                if r['rr_type'] == rr_type.upper() and r['id'] == int(rid): # otherwise it might be a different type of record
                    found = True
                    break
        if found == False:
            raise Exception("id/type mismatch")
        options = kwargs.get('options',None)
        if options != None:
            options = self._pack_options(options)
        else:
            options = ""
        values = {}
        vals = self._fixup_values(rr_type, value)
#        values = values | vals
        values = merge_dicts(values,vals)
        values['options'] = options
        sql="UPDATE records SET {} WHERE id = {}".format(', '.join(list(map(lambda a: a+" = :"+a, values.keys()))), rid)
        return self._query(sql, values)

    def delete_record(self, *args, **kwargs):
        fqdn = args[0]
        force = kwargs.get('force',False)
        if fqdn == None:
            raise Exception("required field not specified")
        recs = self.find_record(fqdn)
        rid = None
        found = False
        if len(recs) == 0:
            raise Exception("record not found")
        else:
            if 'id' not in kwargs:
                raise Exception("id Missing")
            rid = kwargs['id']
            for r in recs:
                if r['id'] == int(rid): # otherwise it might be a different type of record
                    found = True
                    break
        if found == False:
            raise Exception("id/type mismatch")
        sql = "SELECT count(*) AS cnt FROM records WHERE record_id = :id"
        recs = self._query(sql, {'id': rid})
        if recs[0]['cnt'] > 0 and force == False:
            raise Exception("record has associations. use -f to clear")
        sql = 'DELETE FROM records WHERE id = :id;'
        return self._query(sql, {'id': rid})

    def find_network(self, *args, **kwargs):
        network = args[0]
        if network == None:
            raise Exception("missing argument")
        net = None
        try:
            net = ipaddress.IPv4Network(network)
        except:
            try:
                net = ipaddress.IPv6Network(network)
            except:
                raise Exception("not valid network")
        low_addr = ipaddress.ip_address(net.network_address).packed
        high_addr = ipaddress.ip_address(net.broadcast_address).packed
        sql="SELECT * FROM fqdn_records WHERE intvalue >= :low and intvalue <= :high ORDER BY intvalue,fqdn ASC;"
        result = self._query(sql, { 'low': low_addr, 'high': high_addr})
        ret = []
        for res in result:
            if 'options' in res:
                options = self._unpack_options(res['options'])
            ret.append({'id': res['id'], 'fqdn': res['fqdn'], 'rr_type': res['rr_type'], 'value': res['value'], 'options': options })
        return(ret)

    def find_address(self, *args, **kwargs):
        address = args[0]
        if address == None:
            raise Exception("missing argument")
        addr = None
        try:
            addr = ipaddress.ip_address(address).packed
        except:
            raise Exception("not valid address")
        sql="SELECT * FROM fqdn_records WHERE intvalue = :ip ORDER BY fqdn ASC;"
        result = self._query(sql, {'ip': addr})
        ret = []
        for res in result:
            if 'options' in res:
                options = self._unpack_options(res['options'])
            ret.append({'id': res['id'], 'fqdn': res['fqdn'], 'rr_type': res['rr_type'], 'value': res['value'], 'options': options })
        return(ret)

    def _splitfqdn(self, fqdn):
        if len(fqdn) == 0:
            return(None, None)
        sp = fqdn.split('.')
        return(sp[0],".".join(sp[1:]))

    def _ip2num(self, addr=None):
        if addr == None:
            raise Exception("value not specified")
        return ipaddress.ip_address(addr).packed

    def _query(self, sql, *args):
        if self.con == None:
            raise Exception("not connected")
        cur = self.con.cursor()
        try:
            cur.execute(sql, args[0])
        except sqlite3.Error as e:
            raise Exception(e)
        # this magic takes the return values and converts them to an array of dicts
        vals = [{k: item[k] for k in item.keys()} for item in cur.fetchall()]
        cur.close()
        self.con.commit()
        return vals

    def _fixup_values(self, rr_type, value):
        vals = {}
        if rr_type in ["A", "AAAA"]:
            vals['intvalue'] = self._ip2num(value)
        elif rr_type in ["CNAME", "MX", "NS", "SRV"]:
            value=value.lower()
            r = self.find_record(value)
            if len(r) == 0:
                raise Exception("could not find main record")
            vals['record_id'] = r[0]['id']
        # add the actual value too
        vals['value'] = value
        return(vals)

    def _unpack_options(self, options=""):
        # take the option DB format and create dict
        vals={}
        opts = ""
        if isinstance(options, dict):
            return(options)
        elif isinstance(options, list):
            opts = " ".join(options)
        elif isinstance(options, str):
            opts = options
        else:
            return(vals)
        if len(options) == 0:
            return(vals)
        for o in opts.split(" "):
            (k,v) = o.split(":")
            vals[k]=v
        return(vals)

    def _pack_options(self, options):
        # take a dict and make the option DB format
        s=[]
        if not isinstance(options, dict):
            return("")
        for k in options.keys():
            s.append("{}:{}".format(k,options[k]))
        return(" ".join(s))

# do not allow ourselved to be alled directly
if __name__ == "__main__":
    raise Exception("cannot call directly")

