#!/usr/bin/env python
#
from mitmproxy import io
from mitmproxy import ctx 
from mitmproxy.exceptions import FlowReadException
import pprint
import difflib
import json
import itertools
from lib.jsonFun import *
from lib.group import *
from lib.flow import *
from lib.rule import *
from lib.fuzz import *


def filter(f): #define rules to be filtered out
    try:                
        if hasattr(f.response, 'status_code'): #
            if f.response.status_code != 200 and f.response.status_code != 302:
                return False
        if hasattr(f.response, 'headers'):
            ct = str(f.response.headers.fields) #content-type
            if ct.find('image/') != -1:
                return False
        if f.request.method == 'POST':
            return True
        if f.request.method == 'GET' :
            if f.request.url.find('?') == -1:
                return False
            return True
    except:
        pass
    return False

def print_info(flow_list, group_list): #for test
    print([f.group for f in flow_list])
    #for i in range(1, len(group_list)):
    #    print(group_list[i].LCS)
    for g in range(1,len(group_list)):
        sys.stdout.write(str(g)+' ')
        pp.pprint(group_list[g])
    i = 0 
    for f in flow_list:
        sys.stdout.write("Index = "+ str(i) + ", Group = " + str(f.group) + "\n")
        pp.pprint(f)
        i += 1

def is_sublist(list1, list2):
    for i in range(0, len(list2)-len(list1)+1):
        if(list1 == list2[i : i+len(list1)]):
            return True
    return False

with open(sys.argv[1], "rb") as logfile:
#with open(ctx.options.file, "rb") as logfile:
    freader = io.FlowReader(logfile)
    pp = pprint.PrettyPrinter(indent=4)
    try:
        flow_list = list()
        for f in freader.stream():
            if filter(f):
                flow_list.append(flow(f))
                #pp.pprint(f.get_state())
            '''
            try:
                print(f.response.cookies['ubid-main'])
            except:
                pass
            '''
        group_list = list()          #list of group_obj
        group_list.append(0)
        i = 1
        group_flag = 0
        #print(is_similar(flow_list[13], flow_list[96]))
        for index in range(0, len(flow_list)): #filter and group
            for index2 in range(index+1, len(flow_list)):
                if is_similar(flow_list[index], flow_list[index2]) and flow_list[index2].group == 0:
                    if(flow_list[index].group == 0):
                        group_list.append(group_obj(flow_list[index], index))
                        flow_list[index].group = i
                        group_flag = 1
                    group_list[i].add(flow_list[index], index2)
                    flow_list[index2].group = i    
            if group_flag:
                i += 1
            group_flag = 0
        
        #cookie_change(group, flow_list)

        '''
        find_LCS(group, group_list)
        LCS_list = list()
        for i in range(1, len(group_list)):
            LCS_list.append(group_list[i].LCS)
        LCS_list.sort(key = len)
        
        rm = list()
        #filter out the sublist of other LCS
        for i in range(0, len(LCS_list)):
            for j in range(i+1, len(LCS_list)):
                if(is_sublist(LCS_list[i], LCS_list[j])):
                    rm.append(LCS_list[i])
                    break
        for i in range(0, len(rm)): 
            LCS_list.remove(rm[i])
        '''
        #find the rules
        dup_value = find_dup(flow_list)
        rule_dict = dict()
        for index in range(len(flow_list)):
            if flow_list[index].group != 0: 
                if flow_list[index].content_type == 'json':
                    for v in dup_value:
                        keys = find_key(v, flow_list[index].content_dict)
                        if len(keys) == 0:
                            pass
                        else:
                            try:
                                rule_dict[v].add(keys, index, 'content')
                            except KeyError:
                                rule_dict[v] = rule(keys, index, 'content')
                    continue
                for item in flow_list[index].content_dict:
                    value = flow_list[index].content_dict[item][0]
                    if value in dup_value:
                        try:
                            rule_dict[value].add(item, index, 'content')
                        except KeyError:
                            rule_dict[value] = rule(item, index, 'content')
                for item in flow_list[index].url_dict:
                    value = flow_list[index].url_dict[item][0]
                    if value in dup_value:
                        try:
                            rule_dict[value].add(item, index, 'url')
                        except KeyError:
                            rule_dict[value] = rule(item, index, 'url')
                for item in flow_list[index].resp_cookies:
                    value = flow_list[index].resp_cookies[item]
                    if value in dup_value:
                        if value in rule_dict.keys():
                            rule_dict[value] = rule(item, index, 'cookies')
                if flow_list[index].resp_content:
                    if flow_list[index].resp_type == 'json':
                        for key, value in flow_list[index].resp_content.items():
                            if (value in dup_value) and (value in rule_dict):
                                rule_dict[value] = rule(key, index, 'resp_content')
                    else:
                        pass 
        '''
        matrix = trans_matrix(len(group_list)+1)
        for i in rule_dict:
            matrix.add(rule_dict[i].group_order(group))
            matrix.subset_cnt(unique(rule_dict[i].group_order(group)))
        '''
        for r in rule_dict.values():
            r.group_order(flow_list) 
        result = {}
        for key,value in rule_dict.items():
            if not rule_exist(value, result):
                result[key] = value
        rule_dict = result
                
        first_mem = [0]  #record the first member of each group
        for i in range(1, len(group_list)):
            first_mem.append(flow_list[group_list[i].member[0]])
        
        for m in first_mem[1:]:
            try:
                for key in m.content_dict.keys():
                    try:
                        m.content_dict[key] = m.content_dict[key][0]
                    except:
                        pass
            except:
                pass

        fuzz_list = list() 
        output = open('fuzz_log', "wb")
        fwriter = io.FlowWriter(output)
        output_rule = {}
        output_rule['value'] = []
        output_rule['ptn_num'] = []
        output_rule['resp_rule'] = [None] * (len(group_list) )
        #for test !!!
        output_rule['resp_rule'][13] = [('content', 'hasMoreItems', 10, 'content', 'count')]
        
        for i in rule_dict:
            #print(rule_dict[i])
            order = rule_dict[i].g_order
            if len(set(order)) == 1 or rule_dict[i].dir == 'resp':
                print(i)
                print([order, rule_dict[i]])
                continue
            #print([i, unique(order) ])
            output_rule['value'].append(i)
            if rule_dict[i].dir == 'resp':
                pdb.set_trace()   
                rule_dict[i].record_resp(output_rule['resp_rule'], flow_list) 
            fuzz_list += rule_fuzz(rule_dict[i], first_mem, flow_list)
            output_rule['ptn_num'].append(rule_dict[i].ptn_num)
        #fuzz_list += other_fuzz(first_mem)
        for i in fuzz_list:
            fwriter.add(i) 
        #print([x for x in sorted(matrix.cnt.items(), key=lambda x:x[1], reverse=True) if x[1]>1])
        output_rule['group'] = len(group_list) - 1
        outfile = open('rule.json', 'w') 
        json.dump(output_rule, outfile)
        print('')
        print_info(flow_list, group_list)

    except FlowReadException as e:
        print("Flow file corrupted: {}".format(e))
