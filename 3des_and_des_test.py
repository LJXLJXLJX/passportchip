Ka1='ab94fdecf2674fdf'
Kb1='b9b391f85d7f76f2'
data='781723860c06c2264608f919887022120b795240cb7049b01c19b33e32804f0b'
from pyDes import * #pyDes.h很长,就不贴上来了,在项目文件夹中存放
import binascii
def KencTDES(data,Ka1,Kb1):
    
    data=binascii.unhexlify(data)
    key=Ka1+Kb1
    key=binascii.unhexlify(key)
    IV='\0\0\0\0\0\0\0\0'
    k=triple_des(key, CBC, IV, pad=None, padmode=PAD_NORMAL)
    dd3=k.encrypt(data)
    dd3=binascii.hexlify(dd3)
   

    Ka1=binascii.unhexlify(Ka1)
    Kb1=binascii.unhexlify(Kb1)
    ka=des(Ka1, CBC, IV, pad=None, padmode=PAD_NORMAL)
    kb=des(Kb1, CBC, IV, pad=None, padmode=PAD_NORMAL)
    d1=ka.encrypt(data)
    print 'd1 is : '+binascii.hexlify(d1)
    d2=kb.decrypt(d1)
    print 'd2 is : '+binascii.hexlify(d2)
    d3=ka.encrypt(d2)
    d3=binascii.hexlify(d3)
    print'the result of 3des and 3 times des is : \n'+dd3+'\n'+d3
    
    print dd3==d3
KencTDES(data,Ka1,Kb1)
