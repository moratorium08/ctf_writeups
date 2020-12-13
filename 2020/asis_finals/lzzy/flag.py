import os
import decimal
import time


with open('result.txt') as f:
    s = f.read()

t = 'ASIS{'
for i in range(len(s)//2):
    x = s[2 * i: 2 * (i + 1)]
    y = int(x, 16)
    
    decimal.getcontext().prec = 2992
    index=i + 100
    x = str(decimal.Decimal(1) / decimal.Decimal((1010 - int(time.strftime('%m')))*1000 +1))[2:]
    x = int(x[3*index:3*index+3])
    t += chr(x^y)
t += '}'
print(t)
