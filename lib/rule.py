import mitmproxy
import sys
from collections import Counter
import csv
import itertools

def calc_value(group, flow_list):
    all_value = list()
    record = dict()
    for index in range(0, len(group)):
        if(group[index] != 0):
            all_value += flow_list[index].get_value()
            for value in flow_list[index].get_value():
                try:
                    record[value].append(group[index])   
                except KeyError:
                    record[value]=[group[index]]
    cnt = Counter(all_value)
    cnt_list = sorted(list(cnt.items()), key = lambda s:s[1], reverse = True)
    cnt_list = [x[0] for x in cnt_list if x[1]>1] 
    
    order_list = [x for x in record.keys() if len(record[x])>1]
    order_tup = map(tuple, order_list)
    order_cnt = sorted(list(Counter(order_tup).items()), key = lambda s:s[1], reverse = True)
    
    return order_list
 
def unique(sequence): #remove duplicate value and keep the order in list
    seen = set()
    return [x for x in sequence if not (x in seen or seen.add(x))]

def cookie_change(group, flow_list):
    pre = set()
    for index in range(len(group)):
        if(group[index] != 0 and flow_list[index].cookies):
            if set(flow_list[index].cookies.items()) - pre:
                sys.stdout.write('Group: ' + str(group[index]) + ' ')
                print(set(flow_list[index].cookies.items()) - pre)
                pre = set(flow_list[index].cookies.items())

def is_sameRule(rule1, rule2):
    if rule1.url != rule2.url:
        return False
    if rule1.content != rule2.content:
        return False          
    if unique(rule1.g_order) != unique(rule2.g_order):
        return False
    return True

def rule_exist(rule, rule_dict):
    for r in rule_dict.values():
        if is_sameRule(rule, r):
            return True
    return False

class rule:
    def __init__(self, key, index, location):
        self.location = [location]
        self.url = list()
        self.content = list()
        if location == 'url':
            self.url.append([key])
            self.content.append([''])
        else:
            self.content.append([key])
            self.url.append([''])
            
        self.order = [index]
        self.g_order = [] 
    def __repr__(self):
        re = ''
        for index in range(0, len(self.order)):
            re += 'Flow ' + str(self.order[index]) + '\n' 
            #re += ' ' + str(self.location[index]) + ' key: '
            re += 'url key: ' + str(self.url[index]) + '\n'
            re += 'content key: ' + str(self.content[index]) + '\n-> '
        return re

    def add(self, key, index, location):
        if(self.order[-1] == index): #in the same flow
            if location == 'url':
                self.url[-1].append(key)
            else:
                self.content[-1].append(key)
        else:
            #self.location.append(location)
            if location == 'url':
                self.url.append([key])
                self.content.append([''])
            else:
                self.content.append([key])
                self.url.append([''])
            self.order.append(index)

    def group_order(self, group):
        self.g_order = [group[x] for x in self.order]
        return [group[x] for x in self.order]

    def fuzz_order(self, group):
        index_tup = [(index, group[index]) for index in self.order]
        seen = list()
        re = list()
        for tup in index_tup:
            if tup[1] in seen:
                pass
            else:
                seen.append(tup[1])
                re.append(tup[0])
        return re

            

class trans_matrix:
    def __init__(self, size):
        self.size = size
        self.matrix = [[0 for x in range(size)] for y in range(size)] 
        self.cnt = Counter()
    
    def __repr__(self):
        re = ''
        for i in range(1, self.size):
            self.matrix[i][i] = 0   
            re += str(i) + str(self.matrix[i][1:]) + '\n'
        re += '\n'
        return re

    def add(self, order):
        for i in range(len(order)-1):
            self.matrix[order[i]][order[i+1]] += 1

    def write(self, name):
        for i in range(self.size):
            self.matrix[i][i] = 0
        with open(name,"w+") as my_csv:
            csvWriter = csv.writer(my_csv,delimiter=',')
            csvWriter.writerows(self.matrix[0:][0:])
        
    def subset_cnt(self, s):
        for i in range(2, len(s)):
            self.cnt.update(itertools.combinations(s, i))
