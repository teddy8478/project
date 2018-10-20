from mitmproxy import io
from mitmproxy import ctx
import os
import sys

def request(flow):
    # Avoid an infinite loop by not replaying already replayed requests
    if flow.request.is_replay:
        return
    flow = flow.copy()
    # Only interactive tools have a view. If we have one, add a duplicate entry
    # for our flow.
    if "view" in ctx.master.addons:
        ctx.master.commands.call("view.flows.add", [flow])
    flow.request.path = "/changed"
    ctx.master.commands.call("replay.client", [flow])


logfile = open('log/amazon/addCart', "rb")
output = open('copy', "wb")
freader = io.FlowReader(logfile)
fwriter = io.FlowWriter(output)
for f in freader.stream():
    #print(dir(f.request))
    fwriter.add(f)
