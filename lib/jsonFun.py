import sys
import json
import pdb

def is_json(data):
    try:
        if isinstance(data, bytes): 
            data = bytes.decode(data)
        json_object = json.loads(data)
    except ValueError as e:
        return False
    return True    

def json_index(key, data):
    keys = key.split(',')
    for k in keys:
        if isinstance(data, list):
            data = data[int(k)]
        elif isinstance(data, dict):
            data = data[k]
    return data

def json_replace(keys, data, value):
    if len(keys) == 1:
        k = keys[0]
        if isinstance(data, list):
            data[int(k)] = value
        elif isinstance(data, dict):
            data[k] = value
        return data
    k = keys.pop(0)
    if isinstance(data, list):
        data[int(k)] = json_replace(keys, data[int(k)], value)
    elif isinstance(data, dict):
        data[k] = json_replace(keys, data[k], value)
    return data
    

def json_extract(data):
    ret = []
    if isinstance(data, list):
        for i in range(len(data)):
            if isinstance(data[i], dict):
                tmp = json_extract(data[i])
                for t in tmp:
                    t[0] = str(i) + ',' + str(t[0])
                ret += tmp
            elif isinstance(data[i], list):
                for index in range(len(data[i])):
                    tmp = json_extract(data[i][index])
                    for t in tmp:
                        t[0] = str(i) + ',' + str(index) + ',' + str(t[0])
                    ret += tmp
            else:
                ret += [[i, data[i]]]
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                tmp = json_extract(v)
                for t in tmp:
                    t[0] = str(k) + ',' + str(t[0])
                ret += tmp
            elif isinstance(v, list):
                for index in range(len(v)):
                    tmp = json_extract(v[index])
                    for t in tmp:
                        t[0] = str(k) + ',' + str(index) + ',' + str(t[0])
                    ret += tmp
            else:
                ret += [[k, v]]
    else:
        pass
    return ret

def json_dict(data):
    if isinstance(data, bytes):
        data = bytes.decode(data)
    re = json_extract(data)
    return {r[0]: r[1] for r in re}


'''
data = '{"data":[{"stuff":[{"onetype":[{"id":1,"name":"John Doe"},        {"id":2,"name":"Don Joeh"}    ]},    {"othertype":[        {"id":2,"company":"ACME"}    ]}]},{"otherstuff":[    {"thing":        [[1,42],[2,2]]    }]}]}'
test = json.loads(data)
pdb.set_trace()
keys = 'data,0,stuff,0,onetype,0,id'.split(',')

print(json_replace(keys, test, 2))
'''


