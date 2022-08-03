#!/usr/bin/env python3

import re

re_base64_line = re.compile(r'^[a-zA-Z0-9+/]+$')

counter=0
out=None
with open("daniel/xyz.pem") as key:
    for key in key:
        if re_base64_line.match(key):
            if out is None:
                out = open(f"daniel/split.{counter}.base64", 'w')
                counter = counter + 1
            out.write(key)
        else:
            if out is not None:
                out.close()
                out = None
if out is not None:
    out.close()