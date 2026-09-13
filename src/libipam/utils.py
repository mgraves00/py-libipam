#
# Copyright 2026 Michael Graves <mg@brainfat.net>
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
import ipaddress

__all__ = [ 'merge_dicts', 'gen_serial', 'clear_records', 'extract_records',
            'rr_cmp', 'net_to_rev', 'rev_addr', 'splitfqdn', 'rr_print', 'revr_print',
            'validate_network', 'stripdomain' ]

def _ipv4_cut(bitmask):
    t=4
    m=min(bitmask // 8, 3)
    return (t-m)

def _ipv6_cut(bitmask):
    t=32
    m=min(bitmask // 4, 31)
    return (t-m)

def validate_network(cidr):
    net = None
    try:
        net = ipaddress.IPv4Network(cidr,False)
    except:
        try:
            net = ipaddress.IPv6Network(cidr,False)
        except:
            return None
    return(str(net))

def net_to_rev(cidr):
    net = None
    c = 0
    try:
        net = ipaddress.IPv4Network(cidr,False)
    except:
        try:
            net = ipaddress.IPv6Network(cidr,False)
        except:
            return None
    bm = net.prefixlen
    if net.version == 4:
        c = _ipv4_cut(bm)
    else:
        c = _ipv6_cut(bm)
    # get the full reverse name, convert to array, remove the begining parts that belong to the address, then rejoin
    rev = '.'.join(net.network_address.reverse_pointer.split('.')[c:])
    return(rev)

def rev_addr(addr):
    rev=None
    try:
        rev=ipaddress.ip_address(str(addr)).reverse_pointer
        rev+="."
    except:
        pass
    return(rev)

def merge_dicts(d1, d2):
    out = d1
    for k in d2.keys():
        out[k] = d2[k]
    return(out)

def gen_serial():
    return int(time.time())

"""
clear_records(clear_list, resource_record_list)

returns an array of resource records minus the record in the clear list
"""
def clear_records(clear_list, resource_record_list):
    ret=[]
    for i, r in enumerate(resource_record_list):
        if r['rr_type'] not in clear_list:
            ret.append(r)
    return(ret)
"""
extract_records(record_type, resouce_record_list)

return an array of resource records of a specific type
"""
def extract_records(record_type,  resouce_recod_list):
    ret=[]
    for i, r in enumerate(resouce_recod_list):
        if r['rr_type'] == record_type:
            ret.append(r)
    return(ret)

"""
rr_cmp(record_a, record_b)

return -1, 0, 1 based upon fqdn and then record type
"""
def rr_cmp(record_a, record_b):
    # sort by name, @ first, then rr_type
    if record_a['fqdn'] < record_b['fqdn']:
        return -1
    elif record_a['fqdn'] > record_b['fqdn']:
        return 1
    else:
        if record_a['rr_type'] < record_b['rr_type']:
            return -1
        elif record_a['rr_type'] > record_b['rr_type']:
            return 1
        else:
            return 0
"""
stripdomain(fqdn, dom)

strips the domain part from the fqdn so that fqdn
will end up being 'name[.sub]' where the sub part
will be presenent only if there isn't another
sub.domain

"""
def stripdomain(fqdn, dom):
    if fqdn == None or dom == None:
        return(None)
    if len(fqdn) == 0 or dom == 0:
        return(fqdn)
    # if fqdn ends with . , then make sure dom does
    if fqdn.endswith('.'):
        if not dom.endswith('.'):
            dom += "."
    # if fqdn does not ends with . , then make sure dom does not
    if not fqdn.endswith('.'):
        if dom.endswith('.'):
            dom = dom[:-1]
    name = fqdn
    if fqdn.endswith(dom):
        name = fqdn.replace("."+dom,"")
    return(name)

def splitfqdn(fqdn, off=0):
    if len(fqdn) == 0:
        return(None, None)
    sp = fqdn.split('.')
    return(sp[off],".".join(sp[(off+1):]))

def rr_print(fmt, **kwargs):
    rr_type = kwargs['rr_type']
    opts = kwargs['options']
#        kwargs = kwargs | opts
    kwargs = merge_dicts(kwargs,opts)
    if kwargs.get('ttl') == None:
        kwargs['ttl'] = ""
    (name, domain) = splitfqdn(kwargs['fqdn'])
    if name == "@":
        kwargs['fqdn'] = domain+"."
    else:
        kwargs['fqdn'] = kwargs['fqdn']+"."
    if rr_type == "SOA":
        kwargs['serial'] = gen_serial()
    # If name is root (.) then send to nothing as root
    # is added later.
    if kwargs['value'] == '.':
        kwargs['value'] = ""
    # now generate the string
    if fmt[rr_type] != None:
        str=fmt[rr_type].format(**kwargs)
    else:
        str=fmt['XX'].format(**kwargs)
    return(str)

def revr_print(fmt, **kwargs):
    str=""
    # reset the rr_type
    rr_type = kwargs['rr_type']
    if rr_type == 'A':
        kwargs['rr_type'] = 'PTR'
        rr_type = 'PTR'
    elif rr_type == 'AAAA':
        kwargs['rr_type'] = 'PTR6'
        rr_type = 'PTR6'
    else:
        return("")
    opts = kwargs['options']
    kwargs = merge_dicts(kwargs,opts)
    if kwargs.get('ttl',None) == None:
        kwargs['ttl'] = ""
    fqdn = kwargs.get('fqdn',None)
    if fqdn != None:
        if fqdn[-1] != '.':
            kwargs['fqdn'] += "."
    if fmt[rr_type] != None:
        str = fmt[rr_type].format(**kwargs)
    return(str)

