#!/usr/bin/env python
#
from mitmproxy import io 
from mitmproxy.exceptions import FlowReadException
import pprint
import difflib
import json
import itertools
from lib.group import *
from lib.flow import *
from lib.rule import *

similarity = 0.999

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

def print_info(flow_list, group, group_list): #for test
    print(group)
    #for i in range(1, len(group_list)):
    #    print(group_list[i].LCS)
    for g in range(1,len(group_list)):
        sys.stdout.write(str(g)+' ')
        pp.pprint(group_list[g])
    
    for i in range(0, len(flow_list)):
        sys.stdout.write("Index = "+ str(i) + ", Group = " + str(group[i]) + "\n")
        pp.pprint(flow_list[i])

def is_sublist(list1, list2):
    for i in range(0, len(list2)-len(list1)+1):
        if(list1 == list2[i : i+len(list1)]):
            return True
    return False

with open(sys.argv[1], "rb") as logfile:
    freader = io.FlowReader(logfile)
    pp = pprint.PrettyPrinter(indent=4)
    try:
        flow_list = list()
        for f in freader.stream():
            if filter(f):
                flow_list.append(flow(f))
    #        if hasattr(f.response, 'headers'):
    #            pp.pprint(f.response.headers)
    #        print("")
        group = [0] * len(flow_list)
        group_list = list()          #list of group_obj
        group_list.append(0)
        i = 1
        group_flag = 0
    #    print(is_similar(flow_list[0], flow_list[1]))
        for index in range(0, len(flow_list)): #filter and group
            for index2 in range(index+1, len(flow_list)):
                if is_similar(flow_list[index], flow_list[index2]) and group[index2] == 0:
                    if(group[index] == 0):
                        group_list.append(group_obj(flow_list[index], index))
                        group[index] = i
                        group_flag = 1
                    group_list[i].add(index2)
                    group[index2] = i                          
                        
            if group_flag:
                i += 1
            group_flag = 0
        
        #cookie_change(group, flow_list)


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
        
        dup_value = calc_value(group, flow_list)
        rule_dict = dict()
        for index in range(0, len(group)):
            if(group[index] != 0):  
                for item in flow_list[index].content_dict:
                    value = flow_list[index].content_dict[item][0]
                    if(value in dup_value):
                        try:
                            rule_dict[value].add(item, index, 'content')
                        except KeyError:
                            rule_dict[value] = rule(item, index, 'content')
                for item in flow_list[index].url_dict:
                    value = flow_list[index].url_dict[item][0]
                    if(value in dup_value):
                        try:
                            rule_dict[value].add(item, index, 'url')
                        except KeyError:
                            rule_dict[value] = rule(item, index, 'url')
        matrix = trans_matrix(len(group_list)+1)
        for i in rule_dict:
            matrix.add(rule_dict[i].group_order(group))
            matrix.subset_cnt(set(rule_dict[i].group_order(group)))
        #count previous group
        for i in rule_dict:
            order = rule_dict[i].group_order(group)
            if len(set(order)) == 1:
                continue
            print([i, rule_dict[i].group_order(group)])
            for index in range(len(order)):
                cur_group = order[index]
                group_list[cur_group].pre_group.update(set(order[:index]))
                group_list[cur_group].dup += 1
            
        #print([x for x in sorted(matrix.cnt.items(), key=lambda x:x[1], reverse=True) if x[1]>1])
        print('')
        '''
        for i in LCS_list:
            sys.stdout.write(str(len(i))+' ')
            print(i) 
        print('')
        '''
        print_info(flow_list, group, group_list)

    except FlowReadException as e:
        print("Flow file corrupted: {}".format(e))
