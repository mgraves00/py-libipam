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

__all__ = [ 'merge_dicts', 'gen_serial', 'clear_records', 'extract_records', 'rr_cmp' ]

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

