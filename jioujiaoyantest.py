

def jioujiaoyan(temp):
    byte=[0,0,0,0,0,0,0,0]
    temp='0x'+temp
    temp=eval(temp)

   
    temp=temp*(16**2)
    for j in [0,1,2,3,4,5,6,7]:
        temp=temp/(16**2)
        byte[j]=temp&0b11111111
        byte[j]=bin(byte[j])[2:]
        num=0
        for i in byte[j]:
            if i=='1':
                num=num+1
        if num%2==0:        ##   1的个数为偶
            if temp%2==0:   ##   最低位是0
                byte[j]=byte[j][0:-1]+'1'
            else:           ##   最低位是1
                byte[j]=byte[j][0:-1]+'0'

        if len(byte[j])!=8:
            byte[j]='0'*(8-len(byte[j]))+byte[j]
    aa='0b'
    for j in [7,6,5,4,3,2,1,0]:
        aa=aa+byte[j]
    aa=eval(aa)
    aa=hex(aa)[2:-1]
    return aa


temp='ab94fdecf2674fd1'
print jioujiaoyan(temp)
