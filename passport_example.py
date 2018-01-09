
c1='00000001'
c2='00000002'


import hashlib
import binascii
##############�õ���Կ����########
def getKseed(MRZinfo):
#    MRZinfo=raw_input('�����������Ϣ : ')#��ʱ���� �������

    sha1=hashlib.sha1()
    sha1.update(MRZinfo)
    return sha1.hexdigest()[0:32]
#############��żУ��###########
def jioujiaoyan(temp):
    byte=[0,0,0,0,0,0,0,0]
    temp='0x'+temp
    temp=eval(temp)

   
    temp=temp*(2**8)#��ʼ��(����֮���forѭ��):����1�ֽ�,��8λ
    for j in [0,1,2,3,4,5,6,7]:
        temp=temp/(2**8)#ÿ������8�ֽ�
        byte[j]=temp&0b11111111
        byte[j]=bin(byte[j])[2:]
        num=0
        for i in byte[j]:
            if i=='1':              
                num=num+1
        if num%2==0:        ##   1�ĸ���Ϊż
            if temp%2==0:   ##   ���λ��0
                byte[j]=byte[j][0:-1]+'1'
            else:           ##   ���λ��1
                byte[j]=byte[j][0:-1]+'0'

        if len(byte[j])!=8: ##����ʡ�Ը�λ'0'
            byte[j]='0'*(8-len(byte[j]))+byte[j]
    aa='0b'
    for j in [7,6,5,4,3,2,1,0]:
       aa=aa+byte[j]
    aa=eval(aa)
    aa=hex(aa)[2:-1]
    while len(aa)!=16:      ##����ʡ�Ը�λ'0'
        aa='0'+aa
    
    return aa

################����bytesum�ֽ������,bytesumΪ�������########
import random
def randomgenerate(bytesnum):
    a=[0]*bytesnum
    for i in range(bytesnum):
        a[i]=random.randint(0,255)
        a[i]=hex(a[i])[2:]
        if len(a[i])!=2:    #����ʡ�Ը��ֽڵ�'0'
            a[i]='0'+a[i]
    a=''.join(a)
    return a

############����������ݽ���TDES����##################
from pyDes import * #pyDes.h�ܳ�,�Ͳ���������,����Ŀ�ļ����д��
import binascii
def KencTDES(data,Ka1,Kb1):
    
    data=binascii.unhexlify(data)
    key=Ka1+Kb1
    key=binascii.unhexlify(key)
    IV='\0\0\0\0\0\0\0\0'
    k=triple_des(key, CBC, IV, pad=None, padmode=PAD_NORMAL)
    dd3=k.encrypt(data)
    dd3=binascii.hexlify(dd3)    
    return dd3
#����������ݽ���TDES���ܣ���ʵ���Լ��ɵ�����ĺ������Է������˾ͷֿ�д�ɣ�################
def iKencTDES(data,Ka1,Kb1):
    data=binascii.unhexlify(data)
    key=Ka1+Kb1
    key=binascii.unhexlify(key)
    IV='\0\0\0\0\0\0\0\0'
    k=triple_des(key, CBC, IV, pad=None, padmode=PAD_NORMAL)
    dd3=k.decrypt(data)
    dd3=binascii.hexlify(dd3)    
    return dd3

###########����Ϣ��֤��MAC,�޳�ʼ������Ҫ��ʼ��,�ȳ�ʼ�����ٴ���ú���#####################
from pyDes import *
import binascii
def KmacDES(data,Ka2,Kb2):
    data=eval('0x'+data)
    data=bin(data)
    data=data[2:]#���'0b'
    while len(data)%8!=0:
        data='0'+data#�����һ���ֽڵ�ǰ��λ���� Ҳ����ʡ�� ����Ӱ��֮��Ľ��
    data=data+'1'#���һλ1
    while len(data)%64!=0:
        data=data+'0'#���0ֱ���ֽڳ���Ϊ8����������
    data=eval('0b'+data)
    data=hex(data)[2:-1]
    n=len(data)/16
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
    y[1]=ka.encrypt(binascii.unhexlify(x[1]))
    y[1]=binascii.hexlify(y[1])
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
        h[i]=binascii.unhexlify(h[i])
        y[i]=ka.encrypt(h[i])
        y[i]=binascii.hexlify(y[i])
        y[i]=binascii.unhexlify(y[i])
    g=kb.decrypt(y[i])
    Mifd=ka.encrypt(g)
    Mifd=binascii.hexlify(Mifd)
    return Mifd
################################################





#############����Kseed###################
MRZinfo='L898902C<369080619406236'#�ĵ����� �������,�趨��ֵ ��ɾ��--------------------------
#MRZinfo='E16000515073112682404152'
Kseed=getKseed(MRZinfo)
print "Kseed is : "+Kseed.upper()


#����Kseed��c1�õ�D1
D1=Kseed[0:32]+c1
print 'D1 is :'+D1.upper()
HD1=hashlib.sha1(binascii.unhexlify(D1)).hexdigest()
print "D1�Ĺ�ϣɢ��ΪHD1: "+HD1.upper()
#�γ�ka1��kb1
nKa1=HD1[0:16]
nKb1=HD1[16:32]
#������żУ��
Ka1=jioujiaoyan(nKa1)
Kb1=jioujiaoyan(nKb1)
#����Kenc
Kenc=Ka1+Kb1
print "Ka1 is : "+Ka1.upper()
print "Kb1 is : "+Kb1.upper()
print "Kenc is : "+Kenc.upper()




#����Kseed��c2�õ�D2
D2=Kseed[0:32]+c2
print 'D2 is :'+D2.upper()
HD2=hashlib.sha1(binascii.unhexlify(D2)).hexdigest()
print "D2�Ĺ�ϣɢ��ΪHD2: "+HD2.upper()
#�γ�ka2��kb2
nKa2=HD2[0:16]
nKb2=HD2[16:32]
temp='ab94fdecf2674fdf'
#������żУ��
Ka2=jioujiaoyan(nKa2)
Kb2=jioujiaoyan(nKb2)
#����Kmac
Kmac=Ka2+Kb2
print "Ka2 is : "+Ka2.upper()
print "Kb2 is : "+Kb2.upper()
print "Kmac is : "+Kmac.upper()


#�������8�ֽڵ�RNDifd��16�ֽڵ�Kifd(�������,���趨��ֵ)
RNDifd=randomgenerate(8)
Kifd=randomgenerate(16)
RNDifd='781723860c06c226'#�������,�趨��ֵ ��ɾ��----------------------------
Kifd='0b795240cb7049b01c19b33e32804f0b'#�������,�趨��ֵ ��ɾ��----------------------------
print 'RNDifd is : '+ RNDifd.upper()
print 'Kifd is : '+Kifd.upper()






#��оƬ���뵽�����8�ֽ�RNDicc(��input ����,�˴���ʱ��������Ϊ�ο�ֵ)
'''
i=0;
while(i!=16):
    RNDicc=raw_input('��������������RNDicc:')
    RNDicc=RNDicc.replace(' ', '')
    i=len(RNDicc)
    if i!=16:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
'''
RNDicc='4608f91988702212'#�������,�趨��ֵ ��ɾ��------------------------------------------------------
print"RNDicc is : "+RNDicc.upper() 
#����RNDifd,RNDicc,Kifd�õ�S
S=RNDifd+RNDicc+Kifd
print 'S is : '+S.upper()

#��Kenc 3des ����S�õ�Eifd(����ģʽCBC ��ʼֵ0x00 00 00 00 00 00 00 00 �����)
Eifd=KencTDES(S,Ka1,Kb1)
print 'Eifd is : '+Eifd.upper()

#��Kmac����Eifd��MAC��Mifd
Mifd=KmacDES(Eifd,Ka2,Kb2)
print 'Mifd is : '+Mifd.upper()

#ƴ��Eifd��Mifd���õ�cmd
cmd=Eifd+Mifd
print 'cmd is : '+cmd.upper()
print '-----------------------------------------------------\n-----------------------------------------------------'








############### IC����ֵcmd resp =Eicc����Micc#########
###############��������ķ���ֵ resp
'''
i=0;
while(i!=80):
    resp=raw_input('��������ķ�����RESP:')
    resp=resp.replace(' ', '')
    i=len(resp)
    if i!=80:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'


'''
#������䷽����� ���趨 ��ɾ��
resp='46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449'#-------------------------------------
print 'resp data is : '+resp.upper()

################���resp �õ�Eicc(32Bytes) ��Micc(16Bytes)######
Eicc=resp[0:64]
Micc=resp[64:]
print 'Eicc is : '+Eicc.upper()
print 'Micc is : '+Micc.upper()
############����(TDES����)Eicc�õ�R#############
R=iKencTDES(Eicc,Ka1,Kb1)
print 'R is : '+R.upper()
############��R����ȡ��RNDifdr �ȽϽ��յ���RND.IFD�����ɵ�RND.IFD####################
RNDifdr=R[16:32]
print '������ȡ�õ���RNDifdr is : '+RNDifdr.upper()
if RNDifdr==RNDifd:
    
    print '�ȽϽ��յ���RND.IFD�����ɵ�RND.IFD: ��һ�µ�'
else:
    print '�ȽϽ��յ���RND.IFD�����ɵ�RND.IFD: ��һ��'


########################################
###############��R����ȡ��Kicc############
Kicc=R[-32:]
print 'Kicc is : '+Kicc.upper()
#����Kifd��Kicc������߼� �õ�SKseed(��ͬ�������Kseed)
SKseed=hex(eval('0x'+Kifd)^eval('0x'+Kicc))[2:-1]
while len(SKseed)!=len(Kicc):    #����ʡ�Ը�λ'0'
    SKseed='0'+SKseed
print 'SKseed is : '+SKseed.upper()
#����SKseed��c1�õ�SD1
SD1=SKseed[0:32]+c1
print 'SD1 is :'+SD1.upper()
HSD1=hashlib.sha1(binascii.unhexlify(SD1)).hexdigest()
print "SD1�Ĺ�ϣɢ��ΪHSD1: "+HSD1.upper()
#�γ�Ska1��Skb1
nSKa1=HSD1[0:16]
nSKb1=HSD1[16:32]
#������żУ��
SKa1=jioujiaoyan(nSKa1)
SKb1=jioujiaoyan(nSKb1)
#����KSenc
KSenc=SKa1+SKb1
print "SKa1 is : "+SKa1.upper()
print "SKb1 is : "+SKb1.upper()
print "KSenc is : "+KSenc.upper()
#����SKseed��c2�õ�SD2
SD2=SKseed[0:32]+c2
print 'SD2 is :'+SD2.upper()
HSD2=hashlib.sha1(binascii.unhexlify(SD2)).hexdigest()
print "SD2�Ĺ�ϣɢ��ΪHSD2: "+HSD2.upper()
#�γ�Ska2��Skb2
nSKa2=HSD2[0:16]
nSKb2=HSD2[16:32]
temp='ab94fdecf2674fdf'
#������żУ��
SKa2=jioujiaoyan(nSKa2)
SKb2=jioujiaoyan(nSKb2)
#����KSmac
KSmac=SKa2+SKb2
print "SKa2 is : "+SKa2.upper()
print "SKb2 is : "+SKb2.upper()
print "KSmac is : "+KSmac.upper()
#ƴ��RNDicc��4�������Ч�ֽں�RNDifd��4�������Ч�ֽ� �õ�SSC
SSC=RNDicc[-8:]+RNDifd[-8:]
print 'SSC is : '+SSC.upper()
###################################







#####################################
########��ȫͨѶ#########
print '############################��ȫͨѶ###################################'
#########ѡ��EF.COM####################
##########��������ֽ�,��������ͷcmdheader########
'''
i=0;
while(i!=8):
    cmdheader=raw_input('�������ֽ����ͷ:')
    cmdheader=cmdheader.replace(' ', '')
    i=len(cmdheader)
    if i!=8:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
    if cmdheader[0:2]!='0C':
        if cmdheader[0:2]!='0c':
            print 'CLA������0C'
            i=0
cmdheader=cmdheader+'80000000'#���
'''
cmdheader='0ca4020c80000000'########�趨��ֵ ��ɾ��-----------------------------------
print 'cmdheader is : '+cmdheader.upper()

###########�������data################
'''
i=0;
while(i!=16):
    data=raw_input('������������:')
    data=data.replace(' ', '')
    data=data+'80'     
    i=len(data)
    if (i>16)or(i%2==1):
        print 'data�������򳤶ȳ������޶���Χ'
        i=0
    else:
        data=data+'0'*(16-i)
        i=len(data)

'''
data='011e800000000000'######�趨��ֵ����ɾ��--------------------------
print 'data is : '+data.upper()



###########��KSenc��������###########
encrypteddata=KencTDES(data,SKa1,SKb1)
print '��KSenc���ܺ������ encrypteddata is : '+encrypteddata.upper()

###########����DO87##########
L=len(encrypteddata)/2+1
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO87='87'+L+'01'+encrypteddata
print 'DO87 is : '+DO87.upper()
###########����CmdHeader ��DO87�õ�M#################
M=cmdheader+DO87
print 'M is : '+M.upper()
############ SSC��1 ############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #��λ�㲻��ʡ�� ���ֳ���
print 'after +1 SSC is : '+SSC.upper()


#############����SSC��M�õ�N(��������DESmac���������)###################
N=SSC+M
print 'N is : '+N.upper()+'(δ��䣬��������DESmac���������)'

##############��KSmac����N��MAC CC#####################
CC=KmacDES(N,SKa2,SKb2)
print 'CC is : '+CC.upper()


##############����DO8E##############################
L=len(CC)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO8E='8E'+L+CC
print 'DO8E is : '+DO8E.upper()
##############�����������ܱ�����APDU#############
L=len(DO87+DO8E)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
protectedAPDU=cmdheader[0:8]+L+DO87+DO8E+'00'
print 'protectedAPDU is : '+protectedAPDU.upper()
##############����eMRTD ic����ӦAPDU##########################
'''

RAPDU=raw_input('���뷵�صĵ�RAPDU:')
RAPDU=RAPDU.replace(' ', '')

'''


RAPDU = '990290008e08fa855a5d4c50a8ed9000'####-------------------------------�趨��ֵ����ɾ��
print 'RAPDU is : '+RAPDU.upper()

###############ͨ������DO99����Ϣ��֤��,��֤RAPDU CC##########################
############### SSC��1 ##############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #��λ�㲻��ʡ�� ���ֳ���
print 'after +1 SSC is : '+SSC.upper()
###############����DO99##################
'''
i=0;
while(i!=4):
    SW=raw_input('���뷵�صĵ�SW(SW1SW2):')
    SW=SW.replace(' ', '')
    i=len(SW)
    if i!=4:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
DO99='9902'+SW #�����MAC���������
'''
DO99='99029000'
##############����SSC��DO99�õ�K(��������DESmac���������)####################
K=SSC+DO99
print 'K is : '+K.upper()+'(δ��䣬��������DESmac���������)'
##############��KSmac����MAC CC`#######
CC1=KmacDES(K,SKa2,SKb2)
print 'CC1 is : '+CC1.upper()


##############��CC���� RAPDU��DO8E�������Ƚ�####################
DO8Er=RAPDU[12:28]
print 'DO8Er is : '+DO8Er.upper()
print 'Is CC1 equals to DO8Er ?'
print CC1.upper()==DO8Er.upper()



##################"Read Binary �����ǰ�ĸ��ֽڣ�"#####################
print '####################"Read Binary �����ǰ�ĸ��ֽڣ�"######################'
#######################################
##########################################
###################������ͷ######################
'''
i=0;
while(i!=8):
    cmdheader=raw_input('�������ֽ����ͷ:')
    cmdheader=cmdheader.replace(' ', '')
    i=len(cmdheader)
    if i!=8:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
    if cmdheader[0:2]!='0C':
        if cmdheader[0:2]!='0c':
            print 'CLA������0C'
            i=0
cmdheader=cmdheader+'80000000'#���
'''
cmdheader='0cb0000080000000'########�趨��ֵ ��ɾ��-----------------------------------
print 'cmdheader is : '+cmdheader.upper()

##########����DO97################
'''
i=0;
while(i!=2):
    LE=raw_input('LE:')
    LE=LE.replace(' ', '')
    i=len(LE)
    if i!=4:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
DO97='9701'+LE #�����MAC���������
'''
DO97='970104'######�趨��ֵ����ɾ��------------------------------------------
print 'DO97 is : '+DO97.upper()
############����cmdheader��DO97�õ�M######################
M=cmdheader+DO97
print 'M is �� '+M.upper()

############ SSC +1 ##################
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #��λ�㲻��ʡ�� ���ֳ���
print 'after +1 SSC is : '+SSC.upper()

#############����SSC��M���õ�N������䣬�����KmacDes��������ɣ�###################
N=SSC+M
print 'N is : '+N.upper()+'δ��䣬�����KmacDes���������'
CC=KmacDES(N,SKa2,SKb2)
print 'CC is �� '+CC.upper()
#############����DO8E##################
L=len(CC)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO8E='8E'+L+CC
print 'DO8E is : '+DO8E.upper()
#############�����������ܱ�����APDU###################
L=len(DO97+DO8E)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
protectedAPDU=cmdheader[0:8]+L+DO97+DO8E+'00'
print 'protectedAPDU is : '+protectedAPDU.upper()
##############����eMRTD ic����ӦAPDU##########################
'''
i=0;
RAPDU=raw_input('���뷵�صĵ�RAPDU:')
RAPDU=RAPDU.replace(' ', '')
'''

RAPDU = '8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000'####-------------------------------�趨��ֵ����ɾ��
print 'RAPDU is : '+RAPDU.upper()

##############ͨ������DO87��DO99���ô�MAC ��֤CC`#####################
############# SSC+1 #############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #��λ�㲻��ʡ�� ���ֳ���
print 'after +1 SSC is : '+SSC.upper()
###############����DO87������ӦAPDU����ȡ��##############
L=RAPDU[2:4]
L=eval('0x'+L)
L=L*2+4
DO87=RAPDU[0:L]
print 'DO87 is : '+DO87

############����SSC,DO87��DO99�õ�K�������KmacDES�����######################
K=SSC+DO87+DO99
print 'K is : '+K
#############��KSmac����MAC################
CC1=KmacDES(K,SKa2,SKb2)
print 'CC1 is : '+CC1.upper()
##############��ȡDO8Er from RAPDU###################
L8799=len(DO87+DO99)#DO87 ��DO99�������DO8E
L8E=RAPDU[L8799+2:L8799+4]
L8E=eval('0x'+L8E)
L8E=L8E*2+4
DO8Er=RAPDU[L8799+4:L8799+L8E]
print 'DO8Er is : '+DO8Er


#####################################################
print 'Is CC1 equals to DO8Er ?'
print CC1.upper()==DO8Er.upper()
#############��KSenc����DO87###############
data1=iKencTDES(DO87[6:],SKa1,SKb1)#���ܺ�����ݻ��ð���䲿��ȥ��
a=range(len(data1))
a.reverse()
for i in a:
    if data1[i]=='0':
        continue
    elif data1[i]=='8':
        break
data1=data1[0:i]                
print '���ܺ������ data1 is : '+data1.upper()
#########��ȡ����########��������������������������������
L=data1[2:4]
L=eval('0x'+L)+2
print L
print '�ṹ������ L is : '+str(L)

##################################
##################################
##################################
############# Read Binary �����ƫ��4��ʼʣ�µ�18�ֽ�####################
print '################### Read Binary �����ƫ��4��ʼʣ�µ�18�ֽ�####################'
###################������ͷ######################
'''
i=0;
while(i!=8):
    cmdheader=raw_input('�������ֽ����ͷ:')
    cmdheader=cmdheader.replace(' ', '')
    i=len(cmdheader)
    if i!=8:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
    if cmdheader[0:2]!='0C':
        if cmdheader[0:2]!='0c':
            print 'CLA������0C'
            i=0
cmdheader=cmdheader+'80000000'#���
'''
cmdheader='0cb0000480000000'########�趨��ֵ ��ɾ��-----------------------------------
print 'cmdheader is : '+cmdheader.upper()
##########����DO97################
'''
i=0;
while(i!=2):
    LE=raw_input('LE:')
    LE=LE.replace(' ', '')
    i=len(LE)
    if i!=4:
        print '����ֵ���ȴ���,�벻Ҫʡ��0'
DO97='9701'+LE #�����MAC���������
'''
DO97='970112'######�趨��ֵ����ɾ��------------------------------------------
print 'DO97 is : '+DO97.upper()
############����cmdheader��DO97�õ�M######################
M=cmdheader+DO97
print 'M is �� '+M.upper()
############ SSC +1 ##################
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #��λ�㲻��ʡ�� ���ֳ���
print 'after +1 SSC is : '+SSC.upper()
#############����SSC��M���õ�N������䣬�����KmacDes��������ɣ�###################
N=SSC+M
print 'N is : '+N.upper()+'δ��䣬�����KmacDes���������'
CC=KmacDES(N,SKa2,SKb2)
print 'CC is �� '+CC.upper()
#############����DO8E##################
L=len(CC)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO8E='8E'+L+CC
print 'DO8E is : '+DO8E.upper()

#############�����������ܱ�����APDU###################
L=len(DO97+DO8E)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
protectedAPDU=cmdheader[0:8]+L+DO97+DO8E+'00'
print 'protectedAPDU is : '+protectedAPDU.upper()
##############����eMRTD ic����ӦAPDU##########################
'''
i=0;
RAPDU=raw_input('���뷵�صĵ�RAPDU:')
RAPDU=RAPDU.replace(' ', '')
'''

RAPDU = '871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000'####-------------------------------�趨��ֵ����ɾ��
print 'RAPDU is : '+RAPDU.upper()

##############ͨ������DO87��DO99���ô�MAC ��֤CC`#####################
############# SSC+1 #############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #��λ�㲻��ʡ�� ���ֳ���
print 'after +1 SSC is : '+SSC.upper()
###############����DO87������ӦAPDU����ȡ��##############
L=RAPDU[2:4]
L=eval('0x'+L)
L=L*2+4
print L
DO87=RAPDU[0:L]
print 'DO87 is : '+DO87.upper()
############����SSC,DO87��DO99�õ�K�������KmacDES�����######################
K=SSC+DO87+DO99
print 'K is : '+K.upper()
#############��KSmac����MAC################
CC1=KmacDES(K,SKa2,SKb2)
print 'CC1 is : '+CC1.upper()
################################################
#######��ȡDO8Er from RAPDU#######################################
L8799=len(DO87+DO99)#DO87 ��DO99�������DO8E
L8E=RAPDU[L8799+2:L8799+4]
L8E=eval('0x'+L8E)
L8E=L8E*2+4
DO8Er=RAPDU[L8799+4:L8799+L8E]
print 'DO8Er is : '+DO8Er.upper()

############################################
print 'Is CC1 equals to DO8Er ?'
print CC1.upper()==DO8Er.upper()

#############��KSenc����DO87###############

data2=iKencTDES(DO87[6:],SKa1,SKb1)#����ȥ����䲿��

a=range(len(data2))
a.reverse()
for i in a:
    if data2[i]=='0':
        continue
    elif data2[i]=='8':
        break
data2=data2[0:i]                

print '���ܺ������ data2 is : '+data2.upper()



EFcom=data1+data2
print '���ս�� EF.COM is : '+EFcom.upper()





















