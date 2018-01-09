from pyDes import *
import binascii
data=binascii.unhexlify('781723860c06c2264608f919887022120b795240cb7049b01c19b33e32804f0b')

key=binascii.unhexlify('ab94fdecf2674fdfb9b391f85d7f76f2ab94fdecf2674fdf')
IV='\0\0\0\0\0\0\0\0'

k=triple_des(key, CBC, IV, pad=None, padmode=PAD_NORMAL)

dd3=k.encrypt(data)

dd3=binascii.hexlify(dd3)


from pyDes import *
import binascii
def KencTDES(data,ka1,kb1):
    
    data=binascii.unhexlify(data)
    key=ka1+kb1+ka1
    key=binascii.unhexlify(key)
    IV='\0\0\0\0\0\0\0\0'
    k=triple_des(key, CBC, IV, pad=None, padmode=PAD_NORMAL)
    dd3=k.encrypt(data)
    dd3=binascii.hexlify(dd3)
    return dd3
    
    
    
