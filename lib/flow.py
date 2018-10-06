import mitmproxy
import sys
import urllib
from difflib import *
import json
from http.cookies import SimpleCookie

def url_to_dict(url):  #return the query key list of the given url
    query = urllib.parse.urlsplit(url).query
    query_dict = urllib.parse.parse_qs(query)

    return query_dict

class flow:
    def __init__(self, stream):
        self.stream = stream
        self.url_dict = url_to_dict(stream.request.url)

        self.raw_content = bytes.decode(stream.request.content)
        self.content_dict = urllib.parse.parse_qs(self.raw_content)
        #self.content_key = list(self.content.keys())
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
        re = 'url key: ' + str(self.url_dict) + '\n'
        re += 'content key: ' + str(self.content_dict) + '\n'
        #re += str(self.stream) + '\n'
        re += 'cookies: ' + str(self.cookies) + '\n\n'
        return re

    def is_json(self):
        try:
            json_object = json.loads(self.raw_content)
        except ValueError as e:
            return False
        return True    
    
    def get_value(self):
        re = list()
        value = list(self.url_dict.values())
        content = list(self.content_dict.values()) 
        
        for element in value:
            if(type(element[0]) == type(str())):
                re += element
        
        for element in content:
            if(type(element[0]) == type(str())):
                re += element
        return re
        
