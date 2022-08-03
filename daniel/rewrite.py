#!/usr/bin/env python

import re

re_snipped = re.compile(r'^\[\s*Snipped[!]\s*\]$')


with open("daniel/xyz.pem") as key,\
     open("daniel/rsa.0.pem") as in0,\
     open("daniel/rsa.1.pem") as in1,\
     open("daniel/out.0.pem", 'w') as out0,\
     open("daniel/out.1.pem", 'w') as out1:
        for k, in0, in1 in zip(key, in0, in1):
            l0 = None
            l1 = None
            if re_snipped.match(k):
                l0 = in0
                l1 = in1
            else:
                l0 = k
                l1 = k
            out0.write(l0)
            out1.write(l1)