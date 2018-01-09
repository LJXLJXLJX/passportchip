'''
dding Method 2
The data string D to be input to the MAC algorithm
shall be right-padded with a single ‘1’bit. The resulting
string shall then be right-padded with as few (possibly
none) ‘O’ bits as necessary to obtain a data stringwhose
length (in bits) is a positive integer multiple of n .
'''


data='72c29c2371cc9bdb65b779b8e8d37b29ecc154aa56a8799fae2f498f76ed92f2'


Ka2='7962d9ece03d1acd'
Kb2='4c76089dce131543'
from pyDes import *
import binascii
def KmacTDES(data,Ka2,Kb2):
    data=eval('0x'+data)
    data=bin(data)
    data=data[2:]#割掉'0b'
    while len(data)%8!=0:
        data='0'+data#即便第一个字节的前四位是零 也不能省略 否则影响之后的结果
    data=data+'1'#填充一位1
    while len(data)%64!=0:
        data=data+'0'#填充0直到字节长度为8的整倍数数
    data=eval('0b'+data)
    print data
    data=hex(data)[2:-1]
    print 'after padding , the data is : '+data



    n=len(data)/16
    print 'n='+str(n)
    x=[0]*(n+1)

    h=[0]*(n+1)
    y=[0]*(n+1)
    Ka2=binascii.unhexlify(Ka2)
    Kb2=binascii.unhexlify(Kb2)

    IV='\0\0\0\0\0\0\0\0'
    ka=des(Ka2, CBC, IV, pad=None, padmode=PAD_NORMAL)
    kb=des(Kb2, CBC, IV, pad=None, padmode=PAD_NORMAL)
    for i in range(n):
        x[i+1]=data[0:16]
        data=data[16:]
        print 'x['+str(i+1)+'] is :'+str(x[i+1])

    print 'x is :'+str(x)
    y[1]=ka.encrypt(binascii.unhexlify(x[1]))
    y[1]=binascii.hexlify(y[1])
    print 'y[1] is : '+y[1]
    y[1]=binascii.unhexlify(y[1])
    for i in range(n+1)[2:]:
        y[i-1]='0x'+binascii.hexlify(y[i-1])
        x[i]='0x'+x[i]
        y[i-1]=eval(y[i-1])
        x[i]=eval(x[i])
        h[i]=x[i]^y[i-1]
        h[i]=hex(h[i])[2:-1]
        if len(h[i])!=16:
            h[i]='0'+h[i]
        print 'h'+str(i)+' is '+h[i]
        h[i]=binascii.unhexlify(h[i])
        y[i]=ka.encrypt(h[i])
        y[i]=binascii.hexlify(y[i])
        print 'y['+str(i)+'] is : '+y[i]
        y[i]=binascii.unhexlify(y[i])
    g=kb.decrypt(y[i])
    Mifd=ka.encrypt(g)
    Mifd=binascii.hexlify(Mifd)
    print 'Mifd is :'+Mifd

   


    
    
KmacTDES(data,Ka2,Kb2)


