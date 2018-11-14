import mitmproxy
import sys
import urllib
import copy
import json
import pdb
from . import jsonFun
from http.cookies import SimpleCookie

time = 0

def replace_json(key, pattern, data):
    for k, v in data.items():
        if isinstance(v, dict):
            data[k] = replace_json(key, pattern, v)
        elif isinstance(v, list):
            for i in range(len(v)):
                data[k][i] = replace_json(key, pattern, v[i])
        else:
            if [k] == key:
                data[k] = pattern
    #pdb.set_trace()
   
    return data

def fetch_json_value(data, key):
    re = []
    #data = bytes.decode(data)
    for k, v in data.items():
        if isinstance(v, dict):
            re += fetch_json_value(v, key)
        elif isinstance(v, list):
            for i in range(len(v)):
                re += fetch_json_value(v[i], key)
        else:
            if k == key:
                return data[k]
            
    return re

def replace_field(flow, value, location, key):
    if location == 'url':
        flow.request.query[key] = value
    else:
        if str(flow.request.headers['content-type']).find('urlencode') > -1:
            dic = urllib.parse.parse_qs(bytes.decode(flow.request.content))
            dic[key] = value
            flow.request.set_text(urllib.parse.urlencode(dic))
        elif str(flow.request.headers['content-type']).find('json') > -1:
            pass
        else:
            pass
    return flow

def find_value(flow, location, key): #return the value in response correspond to the key
    raw_cookie = dict(flow.response.headers.fields).get(b'set-cookie')
    cookie = SimpleCookie()
    resp_cookies = {}
    if(type(raw_cookie) == type(b'cookie')):
        cookie.load(bytes.decode(raw_cookie))
        for k, value in cookie.items():
            resp_cookies[k] = value.value
    data = bytes.decode(flow.response.content)
    if location == 'cookie':
        return resp_cookies[key]
    else:
        if str(flow.response.headers['content-type']).find('urlencode') > -1:
            dic = urllib.parse.parse_qs(data)
            return dic[key]
        elif jsonFun.is_json(flow.response.content):
            pdb.set_trace()
            data.replace('\n', '')
            data.replace(' ','')
            return fetch_json_value(json.loads(data), key)            

def rule_fuzz(rule, member, flow_list):
    order = rule.fuzz_order(flow_list)
    select = list() #record the index in the rule that contain the rule value
    for index in order:
        select.append(rule.order.index(index))
    
    f = open('wordlist/for_test.txt', 'r')
    pattern = list()
    for line in f:
        pattern.append(line[:-1])
     
    return_list = list()
    global time
    rule.set_ptn_num(len(pattern) )
    for p in pattern:
        ret_mem = [0]
        for m in member[1:]: #copy new stream and content_dict into tuple
            copy_dict = m.content_dict.copy()
            copy_stream = m.stream.copy()
            copy_stream.request.timestamp_start= time
            time += 1
            ret_mem.append((copy_stream, copy_dict))
        for s in select:
           g = flow_list[rule.order[s]].group
           if rule.url[s] == ['']:
               if flow_list[rule.order[s]].content_type == 'json':
                   #pdb.set_trace()
                   j_dict = json.loads(flow_list[rule.order[s]].raw_content)
                   tmp_dict = {}
                   for key in rule.content[s]:
                       #pdb.set_trace()
                       keys = key[0].split(',')
                       tmp_dict = jsonFun.json_replace(keys, j_dict , p)
                   ret_mem[g][0].request.set_text(json.dumps(tmp_dict))
                   #print(json.dumps(tmp_dict))
               else:
                   for key in rule.content[s]:
                       ret_mem[g][1][key] = p
           else:
               for key in rule.url[s]:
                   ret_mem[g][0].request.query[key] = p
           if flow_list[rule.order[s]].content_type == 'urlencode':
                ret_mem[g][0].request.set_text(urllib.parse.urlencode(ret_mem[g][1]))
        return_list += [tup[0] for tup in ret_mem[1:]]
    return return_list

def other_fuzz(member):
    pattern = list()
    f = open('wordlist/for_test.txt', 'r')
    for line in f:
        pattern.append(line[:-1])
    ret_list = list()
    for m in member[1:]:
        for key in m.stream.request.query.keys():
            for p in pattern:
                copy_stream = m.stream.copy()
                copy_stream.request.query[key] = p
                ret_list.append(copy_stream)
        if m.content_type == 'urlencode':
            for key in m.content_dict.keys():
                for p in pattern:
                    copy_dict = m.content_dict.copy()
                    copy_stream = m.stream.copy()
                    copy_dict[key] = p
                    copy_stream.request.set_text(urllib.parse.urlencode(copy_dict))
                    ret_list.append(copy_stream)
        elif m.content_type == 'json':
            for key in m.content_dict.keys():
                for p in pattern:
                    keys = key.split(',')
                    copy_stream = m.stream.copy()
                    j_dict = json.loads(m.raw_content)
                    copy_stream.request.set_text(json.dumps(jsonFun.json_replace(keys, j_dict, p)))
                    ret_list.append(copy_stream)
                
        ret_list.append(m.stream)
    return ret_list 

