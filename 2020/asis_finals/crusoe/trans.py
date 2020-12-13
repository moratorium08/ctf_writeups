
alpha = '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
#alpha = 'c'


cur = 0
mapping = dict()

def gen_map(s):
    global cur
    if s in mapping:
        print('exists')
    mapping[s] = alpha[cur]
    cur += 1

def trans(callback, name):
    with open(name) as f:
        l = f.read().split('\n')[:-1]
    for i in range(len(l) // 5):
        line = l[5 * i: 5 * (i+1)]
        for j in range(len(line[0]) // 9):
            x = 9 * j
            y = 9 * (j+1)
            callback('\n'.join([tmp[x:y] for tmp in line]))


def generate(s):
    import os
    with open('input', 'w') as f:
        f.write(s)
    os.system('cat input | ./crusoe > output')


seq = []

def genseq(s):
    seq.append(s)

trans(genseq, 'flag.crusoe')
print(len(seq))

s = ''
cur = 0
for i in range(64):
    for c in alpha:

        tmp = s + c
        generate(tmp)

        seq2 = []
        trans(lambda s: seq2.append(s), 'output')

        seq2 = seq2[:-1]
        flag = True
        if len(seq2) > len(seq):
            continue
        for j in range(len(seq2)):
            if seq[j] != seq2[j]:
                #print(seq[j])
                #print(seq2[j])
                flag = False
        if flag:
            s = tmp
            cur = len(seq2)
            break
    if cur >= 64:
        break

print(s)

