from mitmproxy import ctx
from bs4 import BeautifulSoup
import html_similarity as hs
from . import flow
import pdb

def compare_resp(flow1, flow2):
    f1 = flow.flow(flow1)
    f2 = flow.flow(flow2)
    #print(f1.resp_type)
    #print(f2.resp_type)
    #pdb.set_trace()
    if f1.resp_type != f2.resp_type:
        ctx.log.error('Unexpected response content type!')
        return
    if f1.resp_type == 'json' and f1.resp_content.keys() != f2.resp_content.keys():
        ctx.log.error('Different json structure!')
        return
    elif f1.resp_type == 'html' :
        sim = hs.structural_similarity(f1.resp_raw, f2.resp_raw)
        ctx.log.error(str(sim))
    
    
