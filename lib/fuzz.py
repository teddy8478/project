import mitmproxy
import sys
import urllib
import copy

time = 0
def rule_fuzz(rule, member, group):
    order = rule.fuzz_order(group)
    select = list() #record the index in the rule that contain the rule value
    for index in order:
        select.append(rule.order.index(index))
    
    f = open('wordlist/for_test.txt', 'r')
    pattern = list()
    for line in f:
        pattern.append(line[:-1])
     
    return_list = list()
    global time
    
    for p in pattern:
        ret_mem = [0]
        for m in member[1:]: #copy new stream and content_dict into tuple
            copy_dict = m.content_dict.copy()
            copy_stream = m.stream.copy()
            copy_stream.request.timestamp_start= time
            time += 1
            ret_mem.append((copy_stream, copy_dict))
        for s in select:
           g = group[rule.order[s]]
           if rule.url[s] == ['']:
               for key in rule.content[s]:
                   ret_mem[g][1][key] = p
           else:
               for key in rule.url[s]:
                   ret_mem[g][0].request.query[key] = p
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
        for key in m.content_dict.keys():
            for p in pattern:
                copy_dict = m.content_dict.copy()
                copy_stream = m.stream.copy()
                copy_dict[key] = p
                copy_stream.request.set_text(urllib.parse.urlencode(copy_dict))
                ret_list.append(copy_stream)
        ret_list.append(m.stream)
    return ret_list 

