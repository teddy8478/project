import mitmproxy
import sys
import urllib
from difflib import *
from bs4 import BeautifulSoup
import json
from http.cookies import SimpleCookie
from mitmproxy.net.http import headers
from mitmproxy.net.http import multipart
import pdb
from . import jsonFun 

def url_to_dict(url):  #return the query key list of the given url
    query = urllib.parse.urlsplit(url).query
    query_dict = urllib.parse.parse_qs(query)

    return query_dict

def json_value(data):
    value = []
#    pdb.set_trace()
    for item in data.values():
        if isinstance(item, dict):
            value += json_value(item)
        elif isinstance(item, list):
            for l in item:
                value += json_value(l)
        else:
            value += [[item]]
    return value 


class flow:
    def __init__(self, stream):
        self.stream = stream
        self.group = 0
        self.url_dict = url_to_dict(stream.request.url)
        self.content_type = ''
        self.resp_type = ''
        self.content_dict = {}
        self.resp_content = {}
        self.raw_content = stream.request.content.decode(encoding="utf-8", errors="replace")
        self.resp_raw = ''
        if((str(stream.request.headers.get("content-type")).find('multipart')) > -1):
            self.content_type = 'multipart'
            form = multipart.decode(stream.request.headers, stream.request.content)
            form = [(tup[0].decode('utf-8', errors="replace"), [tup[1].decode('utf-8', errors="replace")]) for tup in form]
            self.content_dict = dict(form)
        elif jsonFun.is_json(self.raw_content):
            self.content_type = 'json'
            self.content_dict = jsonFun.json_dict(json.loads(self.raw_content))
        else:
            self.content_type = 'urlencode'
            self.content_dict = urllib.parse.parse_qs(self.raw_content)
        #self.content_key = list(self.content.keys())
        try:
            self.resp_raw = bytes.decode(stream.response.content)
            if((str(stream.response.headers.get("content-type")).find('multipart')) > -1):
                form = multipart.decode(stream.response.headers, stream.response.content)
                form = [(tup[0].decode('utf-8', errors="replace"), [tup[1].decode('utf-8', errors="replace")]) for tup in form]
                self.resp_content = dict(form)
                self.resp_type = 'multipart'
            elif jsonFun.is_json(stream.response.content):
                self.resp_type = 'json'
                self.resp_content = jsonFun.json_dict(json.loads(self.stream.response.content))
            elif str(stream.response.headers.get("content-type")).find('urlencode') > -1:
                self.resp_content = urllib.parse.parse_qs(self.stream.response.content)
            elif BeautifulSoup(self.resp_raw, "html.parser").find():
                self.resp_type = 'html'
        except:
            pass
        #print(self.resp_content)
        raw_cookie = dict(stream.request.headers.fields).get(b'cookie')
        cookie = SimpleCookie()
        if(type(raw_cookie) == type(b'cookie')):
            cookie.load(bytes.decode(raw_cookie))
        self.cookies = {}
        for key, value in cookie.items():
            self.cookies[key] = value.value
        
        self.resp_cookies = {}
        if(hasattr(stream.response, 'headers')):
            raw_cookie = dict(stream.response.headers.fields).get(b'set-cookie')
            cookie = SimpleCookie()
            if(type(raw_cookie) == type(b'cookie')):
                cookie.load(bytes.decode(raw_cookie))
            for key, value in cookie.items():
                self.resp_cookies[key] = value.value
    
    def __repr__(self):
        re = 'url query: ' + str(self.url_dict) + '\n'
        re += 'content query: ' + str(self.content_dict) + '\n'
        #re += str(self.stream) + '\n'
        re += 'url: ' + str(self.stream.request.url) + '\n'
        re += 'Response type: ' + str(self.resp_type) + '\n\n'
        return re
    '''
    def is_json(self):
        try:
            json_object = json.loads(self.raw_content)
        except ValueError as e:
            return False
        return True    
    '''
    def get_value(self):
        re = list()
        value = list(self.url_dict.values())
        if self.content_type == 'urlencode':
            content = list(self.content_dict.values()) 
        else:
            content = json_value(json.loads(self.raw_content))
        
        for element in value:
            if(type(element[0]) == type(str())):
                re += element
        
        for element in content:
            if(type(element[0]) == type(str())):
                re += element
        
        if self.resp_content:
            if self.resp_type == 'json':
                for element in self.resp_content.values():
                    re += [element]
            else:
                pass

        if self.resp_cookies:
            for element in self.resp_cookies.values():
                re += element
        return re
        
