import mitmproxy
import sys
import urllib
import numpy as np
from difflib import *
from . import flow
import re
import json
from collections import Counter

def key_cmp(key1, key2):
    diff1 = list(set(key1) - set(key2))
    diff1.sort(key = len)
    diff2 = list(set(key2) - set(key1))
    diff2.sort(key = len)
    if(len(key1) != len(key2)):
        return False
    if(len(diff1) == 0):
        return True

    for i in range(0, len(diff1)):
        parse1 = re.split('[-.#$_]', diff1[i])
        parse2 = re.split('[-.#$_]', diff2[i])
        if(len(parse1) == 1):
            return False
        for j in range(0, len(parse1)):
            if(len(parse1[j]) != len(parse2[j])):
                return False
    return True

def is_similar(f1, f2):
    if(f1.stream.request.method != f2.stream.request.method):
        return False
    if len(f1.url_dict.keys()) == 0:
        pass
    elif key_cmp(list(f1.url_dict.keys()), list(f2.url_dict.keys())):
        return True

    if(len(f1.content_dict.keys()) == 0 or len(f2.content_dict.keys()) == 0):
        pass
    elif(f1.is_json() and f2.is_json()):
        a, b = json.dumps(f1.raw_content, sort_keys=True), json.dumps(f2.raw_content, sort_keys=True)
        if a == b:
            return True
    else:
        if(key_cmp(list(f1.content_dict.keys()), list(f2.content_dict.keys()))):
            return True

    return False


def lcs(X, Y, m, n): #https://www.geeksforgeeks.org/printing-longest-common-subsequence/ 
    L = [[0 for x in range(n+1)] for x in range(m+1)] 
    for i in range(m+1): 
        for j in range(n+1): 
            if i == 0 or j == 0: 
                L[i][j] = 0
            elif X[i-1] == Y[j-1]: 
                L[i][j] = L[i-1][j-1] + 1
            else: 
                L[i][j] = max(L[i-1][j], L[i][j-1]) 
    index = L[m][n] 
    lcs = [""] * (index+1) 
    lcs[index] = "" 
    i = m 
    j = n 
    while i > 0 and j > 0: 
        if X[i-1] == Y[j-1]: 
            lcs[index-1] = X[i-1] 
            i-=1
            j-=1
            index-=1
        elif L[i-1][j] > L[i][j-1]: 
            i-=1
        else: 
            j-=1
    lcs.pop()
    return lcs
    

def find_LCS(group, group_list):
    for i in range(1, len(group_list)):
        mem = group_list[i].member
        mem.append(len(group)-1)
        seq = list()
        for j in range(0, len(mem)):
            if(mem[j] == len(group)-1):
                break
            seq.append(group[mem[j] : mem[j+1]-1])
        pre = list(filter((0).__ne__, seq[0]))
        for j in range(1, len(seq)):
            seq[j] = list(filter((0).__ne__, seq[j]))
            pre = lcs(pre, seq[j], len(pre), len(seq[j]))
        mem.pop() 
        group_list[i].set_LCS(pre)


class group_obj:
    def __init__(self, flow, index):
        self.member = list()
        self.member.append(index)
        self.url_dict = [flow.url_dict]
        self.LCS = []
        self.pre_group = Counter() 
        self.content_dict = [flow.content_dict]
        #self.diff_key = list()
        self.dup = 0
        self.method = flow.stream.request.method
 
    def __repr__(self):
        re = 'member: ' + str(self.member) + '\n  LCS: ' + str(self.LCS) + '\n'
        #re += '  previous group: ' + self.cnt_prob() + '\n'
        re += '  url key: ' + str(self.url_dict[0].keys()) + '\n'
        re += '  content key: ' + str(self.content_dict[0].keys()) + '\n'
        re += '  method: ' + str(self.method) + '\n'
        return re

    def add(self, flow, index):
        self.member.append(index)
        self.url_dict.append(flow.url_dict)
        self.content_dict.append(flow.content_dict)

    def get_member(self):
        return self.member

    def set_LCS(self, LCS):
        self.LCS = LCS

    def cnt_prob(self):
        for key in self.pre_group:
            self.pre_group[key] /= self.dup 
            self.pre_group[key] = round(self.pre_group[key] * 100)
        return str(self.pre_group)
