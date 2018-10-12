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

def cookie_change(group, flow_list):
    pre = set()
    for index in range(len(group)):
        if(group[index] != 0 and flow_list[index].cookies):
            if set(flow_list[index].cookies.items()) - pre:
                sys.stdout.write('Group: ' + str(group[index]) + ' ')
                print(set(flow_list[index].cookies.items()) - pre)
                pre = set(flow_list[index].cookies.items())

class rule:
    def __init__(self, key, index, location):
        self.location = [location]
        self.key = [[key]]
        self.order = [index]
    
    def __repr__(self):
        re = ''
        for index in range(0, len(self.order)):
            re += 'Flow ' + str(self.order[index]) 
            re += ' ' + str(self.location[index]) + ' key: '
            re += str(self.key[index]) + '\n-> '
        return re

    def add(self, key, index, location):
        if(self.order[-1] == index):
            self.key[-1].append(key)
        else:
            self.location.append(location)
            self.key.append([key])
            self.order.append(index)

    def group_order(self, group):
        return [group[x] for x in self.order]

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
