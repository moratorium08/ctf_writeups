insts = open('nue').read().strip('\n').split('\n')


#insts = [int(s.replace('０', '1').replace('１', '0'), 2) for s in insts]
insts = [int(s.replace('１', '1').replace('０', '0'), 2) for s in insts]



opcodes = ['MNZ',
           'MLZ',
           'ADD',
           'SUB',
           'AND',
           'OR' ,
           'XOR',
           'ANT',
           'SL' ,
           'SRL',
           'SRA',]

types = ['', 'A', 'B', 'C']
for i, inst in enumerate(insts):
    def get_val(i, s):
        tmp = (inst >> i) & ((2 ** s) - 1)
        return int(bin(tmp)[2:].rjust(s, '0')[::-1], 2)

    opcode = get_val(48 + 6, 4)
    #print(bin(get_val(48 + 6, 0b1111)), bin(opcode))

    addr1 =  get_val(32 + 6, 16)
    type1 =  get_val(32 + 4, 2)
    if addr1 >= 2 ** 15:
        addr1 = - ((2 ** 16) - addr1)
    addr2 =  get_val(16 + 4, 16)
    type2 =  get_val(16 + 2, 2)
    if addr2 >= 2 ** 15:
        addr2 = - ((2 ** 16) - addr2)
    addr3 =  get_val(0 + 2, 16)
    type3 =  get_val(0 + 0, 2)
    if addr3 >= 2 ** 15:
        addr3 = - ((2 ** 16) - addr3)

    #print(opcode)
    opcode = opcodes[opcode]
    type1 = types[type1]
    type2 = types[type2]
    type3 = types[type3]

    print('{}. {} {}{} {}{} {}{};'.format(i, opcode, type1, addr1, type2, addr2, type3, addr3))

