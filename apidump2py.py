#/*
# * Copyright (c) 2018 Cisco and/or its affiliates.
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at:
# *
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */
#
# A proof-of-concept script to take the text output of 
# "api trace custom-dump /filename" and convert it into an
# executable python script, thus creating a more realistic
# and flexible environment for replays.
#
# Written by Andrew Yourtchenko (ayourtch at gmail) over a course of
# a couple of days to facilitate a reproduction an issue seen in the field. 
#
# Consequently - this has only a few messages, and may not be as pretty as
# it is possible. But if you find this useful, feel free to improve
# and send pull requests.
#
#
# Things to do:
#
# 1) Make the individual parsers more robust to the output format changes.
#    Just indexing is very fragile, even if it works for proof-of-concept.
# 2) Since we are generating python, we can get clever about sw_if_index and similar numeric IDs,
#    which are passed around:
#    match them from the original trace, and generate the code that does not have them hard-coded.
#    With that functionality the output of this script is halfway-ready "make test" material.

import pprint
import fileinput

import collections
import socket
import binascii
Ip46Address = collections.namedtuple('Ip46Address', ['is_ip6', 'addr', 'af', 'addr_len' ])

def str2mac(mac):
  return binascii.unhexlify(mac.replace(':', ''))

def ip46addr(addr_str):
  a = addr_str.split("/")
  is_ip6 = 0
  af = socket.AF_INET if is_ip6 == 0 else socket.AF_INET6
  try:
    addr = socket.inet_pton(af, a[0])
  except:
    is_ip6 = 1
    af = socket.AF_INET if is_ip6 == 0 else socket.AF_INET6
    addr = socket.inet_pton(af, a[0])
  addr_len = 0 if len(a) < 2 else int(a[1])
  out = Ip46Address(is_ip6=is_ip6, addr=addr, af=af, addr_len=addr_len)
  # pprint.pprint(out)
  return out


# This is the "preamble" and the "postamble" of the generated script.
# Having two copies of the helper functions is not very elegant but keeps it all
# self-contained.

script_head = '''

from __future__ import print_function

import os
import fnmatch
import logging
import pprint


from vpp_papi import VPP

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet
from socket import inet_pton, AF_INET, AF_INET6
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6ExtHdrRouting
from scapy.layers.inet6 import IPv6ExtHdrFragment

import collections
import socket
import binascii
Ip46Address = collections.namedtuple('Ip46Address', ['is_ip6', 'addr', 'af', 'addr_len' ])

def str2mac(mac):
  return binascii.unhexlify(mac.replace(':', ''))

def ip46addr(addr_str):
  a = addr_str.split("/")
  is_ip6 = 0
  af = socket.AF_INET if is_ip6 == 0 else socket.AF_INET6
  try:
    addr = socket.inet_pton(af, a[0])
  except:
    is_ip6 = 1
    af = socket.AF_INET if is_ip6 == 0 else socket.AF_INET6
    addr = socket.inet_pton(af, a[0])
  addr_len = 0 if len(a) < 2 else int(a[1])
  out = Ip46Address(is_ip6=is_ip6, addr=addr, af=af, addr_len=addr_len)
  # pprint.pprint(out)
  return out

# first, construct a vpp instance from vpp json api files
# this will be a header for all python vpp scripts

# directory containing all the json api files.
# if vpp is installed on the system, these will be in /usr/share/vpp/api/
vpp_json_dir = os.environ['VPP'] + '/build-root/install-vpp_debug-native/vpp/share/vpp/api/core'

# construct a list of all the json api files
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
    for filename in fnmatch.filter(filenames, '*.api.json'):
        print(filename)
        jsonfiles.append(os.path.join(vpp_json_dir, filename))

jsonfiles.append(os.environ['VPP'] + '/build-root/install-vpp_debug-native/vpp/share/vpp/api/plugins/acl.api.json')

if not jsonfiles:
    print('Error: no json api files found')
    exit(-1)

# use all those files to create vpp.
# Note that there will be no vpp method available before vpp.connect()
vpp = VPP(jsonfiles)
r = vpp.connect('trace-replay-test')
print(r)
# None

# You're all set.
# You can check the list of available methods by calling dir(vpp)

logger = logging.getLogger('vpp_serializer')
logger.setLevel(logging.DEBUG)

# show vpp version
rv = vpp.api.show_version()
print('VPP versionc_=', rv.version.decode().rstrip('\\0x00'))


'''

script_tail = '''

r = vpp.disconnect()
print(r)
# 0
 
exit(r)


'''

global accumulator, parser
accumulator = {}
parser = None

# a helper function to turn a signed int into an unsigned int represented as string
def unsign(d):
  d = int(d)
  if d >= 0:
    return "%d" % d
  else:
    return "%d" % (d + 2**32)


# methods for API call conversion - one method generally converts one API call

def memclnt_create(w):
  print ("# memclnt create"+ str(w))

def want_ip4_arp_events(w):
  print ("# want_ip4_arp_events"+ str(w))

def sw_interface_dump(w):
  print("rv = vpp.api.sw_interface_dump()")

def control_ping(w):
  print("rv = vpp.api.control_ping()")

def sw_interface_tag_add_del(w):
  print("rv = vpp.api.sw_interface_tag_add_del(sw_if_index=" + w[1] + ", tag='" + w[3] + "')")

def sw_interface_set_flags(w):
  updown = 1 if w[2] == 'admin-up'  else 0
  print("rv = vpp.api.sw_interface_set_flags(sw_if_index=" + w[1] + ", admin_up_down=" + str(updown) + ")")
  # print("# sw_interface_set_flags")

def create_vlan_subif(w):
  print("rv = vpp.api.create_vlan_subif(sw_if_index=" + w[1] + ", vlan_id=" + w[3] + ")")
  # print("create_vlan_subif")

def l2_interface_vlan_tag_rewrite(w):
  # SCRIPT: l2_interface_vlan_tag_rewrite sw_if_index 4 vtr_op 3 push_dot1q 0 tag1 0 tag2 0 (end: ['0']
  print("rv = vpp.api.l2_interface_vlan_tag_rewrite(sw_if_index=" + w[1] + ", vtr_op=" + w[3] +  ", push_dot1q="+ w[5]+ ", tag1="+ w[7]+ ", tag2="+ w[9]+ ")")
  # print("l2_interface_vlan_tag_rewrite")

def sw_interface_add_del_address(w):
  print("a = ip46addr('" + w[2] + "')")
  print("rv = vpp.api.sw_interface_add_del_address(sw_if_index=" + w[1] + ", is_add=1, is_ipv6=a.is_ip6, del_all=0, address_length=a.addr_len, address=a.addr)")
  # print("# sw_interface_add_del_address")

def create_vhost_user_if(w):
  print("rv = vpp.api.create_vhost_user_if(sock_filename='" + w[1] +  "', tag='"+ w[3]+ "')")
  # print("# create_vhost_user_if")

def bridge_domain_dump(w):
  print("rv = vpp.api.bridge_domain_dump()")
  # print("# bridge_domain_dump")

def bridge_domain_add_del(w):
  if w[2] == 'del':
    print("rv = vpp.api.bridge_domain_add_del(bd_id=" + w[1] + ", is_add=0)")
  else:
    print("rv = vpp.api.bridge_domain_add_del(bd_id=" + w[1] + ", flood=" + w[3] + ", uu_flood=" + w[5] + ", forward=" + w[7]+ ", learn=" + w[9] + ", arp_term=" + w[11] + ", mac_age=" + w[13] + ", is_add=1)")
  # print("# bridge_domain_add_del")

def sw_interface_set_l2_bridge(w):
  print("# sw_interface_set_l2_bridge")

def vxlan_add_del_tunnel(w):
  print("adrs = ip46addr('" + w[1] + "')")
  print("adrd = ip46addr('" + w[3] + "')")
  print("rv = vpp.api.vxlan_add_del_tunnel(is_add=1, is_ipv6=adrs.is_ip6, instance=" + unsign(w[9]) + ", src_address=adrs.addr, dst_address=adrd.addr, decap_next_index=" + unsign(w[5]) + ", vni=" + unsign(w[7]) + ")")
  # print("# vxlan_add_del_tunnel")


# ACL command is trickier since it is multiline - so collect the output from multiple lines and form a single API call

# SCRIPT: acl_add_replace 2 count 3 tag net-vpp.secgroup:443a337d-92a9-4cbf-a666-e78ef910c302.from-vpp \ (end: ['\\']
# acl_add_replace
# ACL_PARSE: ['ipv4', 'permit', '\\']
# ACL_PARSE: ['src', '0.0.0.0/0', 'dst', '0.0.0.0/0', '\\']
# ACL_PARSE: ['proto', '1', '\\']
# ACL_PARSE: ['sport', '0-255', 'dport', '0-255', '\\']
# ACL_PARSE: ['tcpflags', '0', 'mask', '0,', '\\']
# ACL_PARSE: ['ipv4', 'permit+reflect', '\\']
# ACL_PARSE: ['src', '70.0.0.9/32', 'dst', '0.0.0.0/0', '\\']
# ACL_PARSE: ['proto', '0', '\\']
# ACL_PARSE: ['sport', '0-65535', 'dport', '0-65535', '\\']
# ACL_PARSE: ['tcpflags', '0', 'mask', '0,', '\\']
# ACL_PARSE: ['ipv4', 'permit+reflect', '\\']
# ACL_PARSE: ['src', '70.0.0.41/32', 'dst', '0.0.0.0/0', '\\']
# ACL_PARSE: ['proto', '0', '\\']
# ACL_PARSE: ['sport', '0-65535', 'dport', '0-65535', '\\']
# ACL_PARSE: ['tcpflags', '0', 'mask', '0,', '\\']
# ACL_PARSE: []


def acl_add_replace_parser(w):
  global parser
  global accumulator
  print("# ACL_PARSE: " + str(w))
  if len(w) == 0 or w[-1] != "\\":
    if accumulator["cur_rule"] != {}:
      accumulator["r"].append(accumulator["cur_rule"])
    # Output the commands 
    accumulator.pop('cmd', None)
    accumulator.pop('cur_rule', None)
    print("acl_args = " + pprint.pformat(accumulator))
    print("rv = vpp.api.acl_add_replace(**acl_args)")
    parser = None
    accumulator = {}
  elif w[0] == 'ipv4' or w[0] == 'ipv6':
    if accumulator["cur_rule"] != {}:
      accumulator["r"].append(accumulator["cur_rule"])
    cr = {}
    cr['is_ipv6'] = 1 if w[0] == 'ipv6' else 0
    cr['is_permit'] = 0;
    if w[1] == "permit":
      cr['is_permit'] = 1
    elif w[1] == "deny":
      cr['is_permit'] = 0
    elif w[1] == "permit+reflect":
      cr['is_permit'] = 2
    elif w[1] == "action":
      cr['is_permit'] = int(w[2])
    accumulator["cur_rule"] = cr
  elif w[0] == 'src':
    adrs = ip46addr(w[1])
    adrd = ip46addr(w[3])
    accumulator["cur_rule"]["src_ip_addr"] = adrs.addr
    accumulator["cur_rule"]["src_ip_prefix_len"] = adrs.addr_len
    accumulator["cur_rule"]["dst_ip_addr"] = adrd.addr
    accumulator["cur_rule"]["dst_ip_prefix_len"] = adrd.addr_len
  elif w[0] == 'proto':
    accumulator["cur_rule"]["proto"] = int(w[1])
  elif w[0] == 'sport':
    sport = w[1].split("-")
    dport = w[3].split("-")
    accumulator["cur_rule"]["srcport_or_icmptype_first"] = int(sport[0])
    accumulator["cur_rule"]["srcport_or_icmptype_last"] = int(sport[1])
    accumulator["cur_rule"]["dstport_or_icmpcode_first"] = int(dport[0])
    accumulator["cur_rule"]["dstport_or_icmpcode_last"] = int(dport[1])
    


def acl_add_replace(w):
  # print("# acl_add_replace")
  global parser
  global accumulator
  accumulator = { 'cmd':"acl_add_replace", 'acl_index':int(unsign(w[0])), 'count':int(w[2]), 'tag':w[4], 'r':[], 'cur_rule':{} }
  parser = acl_add_replace_parser
  # pprint.pprint(a)


# acl_interface_set_acl_list is a two-line output, so needs a parser helper as well

# SCRIPT: acl_interface_set_acl_list sw_if_index 5 count 4
#    input 1 3 output 0 2

def acl_interface_set_acl_list_parser(w):
  global parser
  global accumulator
  pprint.pprint(w)
  res_s = []
  accumulator["n_input"] = 0
  if len(w) > 1:
    if "output" in w:
      output_pos = w.index("output")
      accumulator["n_input"] = output_pos-1
      res_s = w[1:output_pos] + w[output_pos+1:]
    else:
      res_s = w[1:]
      accumulator["n_input"] = len(res_s)
  accumulator["acls"] = map(int, res_s)
  accumulator.pop('cmd', None)
  print("acl_args = " + pprint.pformat(accumulator))
  print("rv = vpp.api.acl_interface_set_acl_list(**acl_args)")
  parser = None
  accumulator = {}
  

def acl_interface_set_acl_list(w):
  global parser
  global accumulator
  accumulator = { 'cmd':"acl_interface_set_acl_list", 'sw_if_index':int(unsign(w[1])), 'count':int(w[3]), 'acls':[] }
  parser = acl_interface_set_acl_list_parser 
  print("# acl_interface_set_acl_list")


# SCRIPT: macip_acl_add count 2 \ (end: ['\\']
# macip_acl_add
# MACIP_ACL_PARSE: ['ipv4', 'permit', '\\']
# MACIP_ACL_PARSE: ['src', 'mac', 'fa:16:3e:61:c7:e9', 'mask', 'ff:ff:ff:ff:ff:ff', '\\']
# MACIP_ACL_PARSE: ['src', 'ip', '0.0.0.0/32,', '\\']
# MACIP_ACL_PARSE: ['ipv4', 'permit', '\\']
# MACIP_ACL_PARSE: ['src', 'mac', 'fa:16:3e:61:c7:e9', 'mask', 'ff:ff:ff:ff:ff:ff', '\\']
# MACIP_ACL_PARSE: ['src', 'ip', '70.0.0.42/32,', '\\']
# MACIP_ACL_PARSE: []


def macip_acl_add_parser(w):
  global parser
  global accumulator
  print("# MACIP_ACL_PARSE: " + str(w))
  if len(w) == 0 or w[-1] != "\\":
    if accumulator["cur_rule"] != {}:
      accumulator["r"].append(accumulator["cur_rule"])
    # Output the commands 
    accumulator.pop('cmd', None)
    accumulator.pop('cur_rule', None)
    print("acl_args = " + pprint.pformat(accumulator))
    print("rv = vpp.api.macip_acl_add(**acl_args)")
    parser = None
    accumulator = {}
  elif w[0] == 'ipv4' or w[0] == 'ipv6':
    if accumulator["cur_rule"] != {}:
      accumulator["r"].append(accumulator["cur_rule"])
    cr = {}
    cr['is_ipv6'] = 1 if w[0] == 'ipv6' else 0
    cr['is_permit'] = 0;
    if w[1] == "permit":
      cr['is_permit'] = 1
    elif w[1] == "deny":
      cr['is_permit'] = 0
    elif w[1] == "action":
      cr['is_permit'] = int(w[2])
    accumulator["cur_rule"] = cr
  elif w[0] == 'src' and w[1] == 'ip':
    adrs = ip46addr(w[2].rstrip(",")) # VPP FIXME this comma should not be there
    accumulator["cur_rule"]["src_ip_addr"] = adrs.addr
    accumulator["cur_rule"]["src_ip_prefix_len"] = adrs.addr_len
  elif w[0] == 'src' and w[1] == 'mac':
    mac_addr = str2mac(w[2])
    mac_addr_mask = str2mac(w[4])


def macip_acl_add(w):
  print("# macip_acl_add")
  global parser
  global accumulator
  accumulator = { 'cmd':"macip_acl_add", 'count':int(w[1]), 'r':[], 'cur_rule':{} }
  parser = macip_acl_add_parser

def macip_acl_del(w):
  print("rv = vpp.api.macip_acl_del(acl_index=" + w[0] +  ")")
  # print("# macip_acl_del")

# SCRIPT: macip_acl_interface_add_del sw_if_index 12 acl_index 2 add (end: ['add']
def macip_acl_interface_add_del(w):
  print("rv = vpp.api.macip_acl_interface_add_del(sw_if_index=" + w[1] + ", acl_index=" + w[3] +  ")")
  # print("# macip_acl_interface_add_del")


def tap_connect(w):
  print("mac = str2mac('" + w[5] + "')")
  print("rv = vpp.api.tap_connect(tap_name='" + w[1] +  "', tag='"+ w[3]+ "')")
  # print("# tap_connect")
 

def delete_vhost_user_if(w):
  print("rv = vpp.api.delete_vhost_user_if(sw_if_index=" + w[1] + ")")
  # print("# delete_vhost_user_if")


print(script_head)

for line in fileinput.input():
  line = line.rstrip('\n').rstrip('\r').rstrip(' ')
  words = line.split()
  if (len(words) > 0 and words[0] == 'SCRIPT:'):
    api_call_name = words[1]
    print("\n# " + line + " (end: " + str(words[-1:]))
    globals()[api_call_name](words[2:])
  elif parser != None:
    parser(words)

print(script_tail)


