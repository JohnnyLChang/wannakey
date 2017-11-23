# coding: utf-8
from random import *
import math

f = open('wannacow.DMP', 'rb')
dump = f.read()
i = 0x14ae9f

def norme(x):
    hist = [0]*256
    for v in x:
        hist[v] += 1
    ret = float(0.0)
    for c in hist:
        if c:
            p = float(c)/float(len(x))
            ret += p*math.log(p)
    if ret == 0.0: return ret
    return -ret / math.log(256.)
            
def miller_rabin(n, k=10):
    if n == 2:
        return True

    if not n & 1:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1:
            return True

        for i in range(s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1
        
    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
        
    for i in range(k):
        a = randrange(2, n - 1)
        if not check(a, s, d, n):
            return False

    return True
                
for i in range(0, len(dump)-128):
    entropy = norme(dump[i:i+128])
    if entropy > 0.7:
        if miller_rabin(int.from_bytes(dump[i:i+128], byteorder='little')):
            print(hex(i))
            print(int.from_bytes(dump[i:i+128], byteorder='little'))
            
