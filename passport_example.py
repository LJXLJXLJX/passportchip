
c1='00000001'
c2='00000002'


import hashlib
import binascii
##############得到密钥种子########
def getKseed(MRZinfo):
#    MRZinfo=raw_input('请输入机读信息 : ')#暂时屏蔽 方便调试

    sha1=hashlib.sha1()
    sha1.update(MRZinfo)
    return sha1.hexdigest()[0:32]
#############奇偶校验###########
def jioujiaoyan(temp):
    byte=[0,0,0,0,0,0,0,0]
    temp='0x'+temp
    temp=eval(temp)

   
    temp=temp*(2**8)#初始化(方便之后的for循环):左移1字节,即8位
    for j in [0,1,2,3,4,5,6,7]:
        temp=temp/(2**8)#每次右移8字节
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

        if len(byte[j])!=8: ##不能省略高位'0'
            byte[j]='0'*(8-len(byte[j]))+byte[j]
    aa='0b'
    for j in [7,6,5,4,3,2,1,0]:
       aa=aa+byte[j]
    aa=eval(aa)
    aa=hex(aa)[2:-1]
    while len(aa)!=16:      ##不能省略高位'0'
        aa='0'+aa
    
    return aa

################生成bytesum字节随机数,bytesum为输入参数########
import random
def randomgenerate(bytesnum):
    a=[0]*bytesnum
    for i in range(bytesnum):
        a[i]=random.randint(0,255)
        a[i]=hex(a[i])[2:]
        if len(a[i])!=2:    #不能省略高字节的'0'
            a[i]='0'+a[i]
    a=''.join(a)
    return a

############用密码对数据进行TDES加密##################
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
    return dd3
#用密码对数据进行TDES解密（其实可以集成到上面的函数，以防玩脱了就分开写吧）################
def iKencTDES(data,Ka1,Kb1):
    data=binascii.unhexlify(data)
    key=Ka1+Kb1
    key=binascii.unhexlify(key)
    IV='\0\0\0\0\0\0\0\0'
    k=triple_des(key, CBC, IV, pad=None, padmode=PAD_NORMAL)
    dd3=k.decrypt(data)
    dd3=binascii.hexlify(dd3)    
    return dd3

###########求消息认证码MAC,无初始化。若要初始化,先初始化好再带入该函数#####################
from pyDes import *
import binascii
def KmacDES(data,Ka2,Kb2):
    data=eval('0x'+data)
    data=bin(data)
    data=data[2:]#割掉'0b'
    while len(data)%8!=0:
        data='0'+data#即便第一个字节的前四位是零 也不能省略 否则影响之后的结果
    data=data+'1'#填充一位1
    while len(data)%64!=0:
        data=data+'0'#填充0直到字节长度为8的整倍数数
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





#############生成Kseed###################
MRZinfo='L898902C<369080619406236'#文档范例 方便调试,设定该值 待删除--------------------------
#MRZinfo='E16000515073112682404152'
Kseed=getKseed(MRZinfo)
print "Kseed is : "+Kseed.upper()


#并置Kseed和c1得到D1
D1=Kseed[0:32]+c1
print 'D1 is :'+D1.upper()
HD1=hashlib.sha1(binascii.unhexlify(D1)).hexdigest()
print "D1的哈希散列为HD1: "+HD1.upper()
#形成ka1和kb1
nKa1=HD1[0:16]
nKb1=HD1[16:32]
#调整奇偶校验
Ka1=jioujiaoyan(nKa1)
Kb1=jioujiaoyan(nKb1)
#生成Kenc
Kenc=Ka1+Kb1
print "Ka1 is : "+Ka1.upper()
print "Kb1 is : "+Kb1.upper()
print "Kenc is : "+Kenc.upper()




#并置Kseed和c2得到D2
D2=Kseed[0:32]+c2
print 'D2 is :'+D2.upper()
HD2=hashlib.sha1(binascii.unhexlify(D2)).hexdigest()
print "D2的哈希散列为HD2: "+HD2.upper()
#形成ka2和kb2
nKa2=HD2[0:16]
nKb2=HD2[16:32]
temp='ab94fdecf2674fdf'
#调整奇偶校验
Ka2=jioujiaoyan(nKa2)
Kb2=jioujiaoyan(nKb2)
#生成Kmac
Kmac=Ka2+Kb2
print "Ka2 is : "+Ka2.upper()
print "Kb2 is : "+Kb2.upper()
print "Kmac is : "+Kmac.upper()


#随机生成8字节的RNDifd和16字节的Kifd(方便调试,先设定该值)
RNDifd=randomgenerate(8)
Kifd=randomgenerate(16)
RNDifd='781723860c06c226'#方便调试,设定该值 待删除----------------------------
Kifd='0b795240cb7049b01c19b33e32804f0b'#方便调试,设定该值 待删除----------------------------
print 'RNDifd is : '+ RNDifd.upper()
print 'Kifd is : '+Kifd.upper()






#向芯片申请到的随机8字节RNDicc(用input 输入,此处暂时将其设置为参考值)
'''
i=0;
while(i!=16):
    RNDicc=raw_input('输入读到的随机数RNDicc:')
    RNDicc=RNDicc.replace(' ', '')
    i=len(RNDicc)
    if i!=16:
        print '输入值长度错误,请不要省略0'
'''
RNDicc='4608f91988702212'#方便调试,设定该值 待删除------------------------------------------------------
print"RNDicc is : "+RNDicc.upper() 
#并置RNDifd,RNDicc,Kifd得到S
S=RNDifd+RNDicc+Kifd
print 'S is : '+S.upper()

#用Kenc 3des 加密S得到Eifd(加密模式CBC 初始值0x00 00 00 00 00 00 00 00 不填充)
Eifd=KencTDES(S,Ka1,Kb1)
print 'Eifd is : '+Eifd.upper()

#用Kmac计算Eifd的MAC，Mifd
Mifd=KmacDES(Eifd,Ka2,Kb2)
print 'Mifd is : '+Mifd.upper()

#拼接Eifd和Mifd，得到cmd
cmd=Eifd+Mifd
print 'cmd is : '+cmd.upper()
print '-----------------------------------------------------\n-----------------------------------------------------'








############### IC返回值cmd resp =Eicc并置Micc#########
###############输入读到的返回值 resp
'''
i=0;
while(i!=80):
    resp=raw_input('输入读到的返回数RESP:')
    resp=resp.replace(' ', '')
    i=len(resp)
    if i!=80:
        print '输入值长度错误,请不要省略0'


'''
#下面语句方便调试 先设定 待删除
resp='46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449'#-------------------------------------
print 'resp data is : '+resp.upper()

################拆解resp 得到Eicc(32Bytes) 和Micc(16Bytes)######
Eicc=resp[0:64]
Micc=resp[64:]
print 'Eicc is : '+Eicc.upper()
print 'Micc is : '+Micc.upper()
############破译(TDES解码)Eicc得到R#############
R=iKencTDES(Eicc,Ka1,Kb1)
print 'R is : '+R.upper()
############从R中提取出RNDifdr 比较接收到的RND.IFD和生成的RND.IFD####################
RNDifdr=R[16:32]
print '破译提取得到的RNDifdr is : '+RNDifdr.upper()
if RNDifdr==RNDifd:
    
    print '比较接收到的RND.IFD和生成的RND.IFD: 是一致的'
else:
    print '比较接收到的RND.IFD和生成的RND.IFD: 不一致'


########################################
###############从R中提取出Kicc############
Kicc=R[-32:]
print 'Kicc is : '+Kicc.upper()
#计算Kifd和Kicc的异或逻辑 得到SKseed(不同于上面的Kseed)
SKseed=hex(eval('0x'+Kifd)^eval('0x'+Kicc))[2:-1]
while len(SKseed)!=len(Kicc):    #不能省略高位'0'
    SKseed='0'+SKseed
print 'SKseed is : '+SKseed.upper()
#并置SKseed和c1得到SD1
SD1=SKseed[0:32]+c1
print 'SD1 is :'+SD1.upper()
HSD1=hashlib.sha1(binascii.unhexlify(SD1)).hexdigest()
print "SD1的哈希散列为HSD1: "+HSD1.upper()
#形成Ska1和Skb1
nSKa1=HSD1[0:16]
nSKb1=HSD1[16:32]
#调整奇偶校验
SKa1=jioujiaoyan(nSKa1)
SKb1=jioujiaoyan(nSKb1)
#生成KSenc
KSenc=SKa1+SKb1
print "SKa1 is : "+SKa1.upper()
print "SKb1 is : "+SKb1.upper()
print "KSenc is : "+KSenc.upper()
#并置SKseed和c2得到SD2
SD2=SKseed[0:32]+c2
print 'SD2 is :'+SD2.upper()
HSD2=hashlib.sha1(binascii.unhexlify(SD2)).hexdigest()
print "SD2的哈希散列为HSD2: "+HSD2.upper()
#形成Ska2和Skb2
nSKa2=HSD2[0:16]
nSKb2=HSD2[16:32]
temp='ab94fdecf2674fdf'
#调整奇偶校验
SKa2=jioujiaoyan(nSKa2)
SKb2=jioujiaoyan(nSKb2)
#生成KSmac
KSmac=SKa2+SKb2
print "SKa2 is : "+SKa2.upper()
print "SKb2 is : "+SKb2.upper()
print "KSmac is : "+KSmac.upper()
#拼接RNDicc的4个最低有效字节和RNDifd的4个最低有效字节 得到SSC
SSC=RNDicc[-8:]+RNDifd[-8:]
print 'SSC is : '+SSC.upper()
###################################







#####################################
########安全通讯#########
print '############################安全通讯###################################'
#########选择EF.COM####################
##########掩码分类字节,并填充命令报头cmdheader########
'''
i=0;
while(i!=8):
    cmdheader=raw_input('输入四字节命令报头:')
    cmdheader=cmdheader.replace(' ', '')
    i=len(cmdheader)
    if i!=8:
        print '输入值长度错误,请不要省略0'
    if cmdheader[0:2]!='0C':
        if cmdheader[0:2]!='0c':
            print 'CLA必须是0C'
            i=0
cmdheader=cmdheader+'80000000'#填充
'''
cmdheader='0ca4020c80000000'########设定该值 待删除-----------------------------------
print 'cmdheader is : '+cmdheader.upper()

###########填充数据data################
'''
i=0;
while(i!=16):
    data=raw_input('输入命令数据:')
    data=data.replace(' ', '')
    data=data+'80'     
    i=len(data)
    if (i>16)or(i%2==1):
        print 'data输入错误或长度超过了限定范围'
        i=0
    else:
        data=data+'0'*(16-i)
        i=len(data)

'''
data='011e800000000000'######设定该值，待删除--------------------------
print 'data is : '+data.upper()



###########用KSenc加密数据###########
encrypteddata=KencTDES(data,SKa1,SKb1)
print '用KSenc加密后的数据 encrypteddata is : '+encrypteddata.upper()

###########构建DO87##########
L=len(encrypteddata)/2+1
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO87='87'+L+'01'+encrypteddata
print 'DO87 is : '+DO87.upper()
###########连接CmdHeader 和DO87得到M#################
M=cmdheader+DO87
print 'M is : '+M.upper()
############ SSC加1 ############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #高位零不能省略 保持长度
print 'after +1 SSC is : '+SSC.upper()


#############连接SSC和M得到N(填充过程在DESmac函数中完成)###################
N=SSC+M
print 'N is : '+N.upper()+'(未填充，填充过程在DESmac函数中完成)'

##############用KSmac计算N的MAC CC#####################
CC=KmacDES(N,SKa2,SKb2)
print 'CC is : '+CC.upper()


##############建立DO8E##############################
L=len(CC)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO8E='8E'+L+CC
print 'DO8E is : '+DO8E.upper()
##############构建并发送受保护的APDU#############
L=len(DO87+DO8E)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
protectedAPDU=cmdheader[0:8]+L+DO87+DO8E+'00'
print 'protectedAPDU is : '+protectedAPDU.upper()
##############接收eMRTD ic的响应APDU##########################
'''

RAPDU=raw_input('输入返回的的RAPDU:')
RAPDU=RAPDU.replace(' ', '')

'''


RAPDU = '990290008e08fa855a5d4c50a8ed9000'####-------------------------------设定该值，待删除
print 'RAPDU is : '+RAPDU.upper()

###############通过计算DO99的消息认证码,验证RAPDU CC##########################
############### SSC加1 ##############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #高位零不能省略 保持长度
print 'after +1 SSC is : '+SSC.upper()
###############构建DO99##################
'''
i=0;
while(i!=4):
    SW=raw_input('输入返回的的SW(SW1SW2):')
    SW=SW.replace(' ', '')
    i=len(SW)
    if i!=4:
        print '输入值长度错误,请不要省略0'
DO99='9902'+SW #填充在MAC函数中完成
'''
DO99='99029000'
##############并置SSC和DO99得到K(填充过程在DESmac函数中完成)####################
K=SSC+DO99
print 'K is : '+K.upper()+'(未填充，填充过程在DESmac函数中完成)'
##############用KSmac计算MAC CC`#######
CC1=KmacDES(K,SKa2,SKb2)
print 'CC1 is : '+CC1.upper()


##############将CC’与 RAPDU的DO8E数据作比较####################
DO8Er=RAPDU[12:28]
print 'DO8Er is : '+DO8Er.upper()
print 'Is CC1 equals to DO8Er ?'
print CC1.upper()==DO8Er.upper()



##################"Read Binary 命令的前四个字节："#####################
print '####################"Read Binary 命令待前四个字节："######################'
#######################################
##########################################
###################填充命令报头######################
'''
i=0;
while(i!=8):
    cmdheader=raw_input('输入四字节命令报头:')
    cmdheader=cmdheader.replace(' ', '')
    i=len(cmdheader)
    if i!=8:
        print '输入值长度错误,请不要省略0'
    if cmdheader[0:2]!='0C':
        if cmdheader[0:2]!='0c':
            print 'CLA必须是0C'
            i=0
cmdheader=cmdheader+'80000000'#填充
'''
cmdheader='0cb0000080000000'########设定该值 待删除-----------------------------------
print 'cmdheader is : '+cmdheader.upper()

##########建立DO97################
'''
i=0;
while(i!=2):
    LE=raw_input('LE:')
    LE=LE.replace(' ', '')
    i=len(LE)
    if i!=4:
        print '输入值长度错误,请不要省略0'
DO97='9701'+LE #填充在MAC函数中完成
'''
DO97='970104'######设定该值，待删除------------------------------------------
print 'DO97 is : '+DO97.upper()
############并置cmdheader和DO97得到M######################
M=cmdheader+DO97
print 'M is ： '+M.upper()

############ SSC +1 ##################
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #高位零不能省略 保持长度
print 'after +1 SSC is : '+SSC.upper()

#############并置SSC和M，得到N（无填充，填充在KmacDes函数中完成）###################
N=SSC+M
print 'N is : '+N.upper()+'未填充，填充在KmacDes函数中完成'
CC=KmacDES(N,SKa2,SKb2)
print 'CC is ： '+CC.upper()
#############建立DO8E##################
L=len(CC)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO8E='8E'+L+CC
print 'DO8E is : '+DO8E.upper()
#############构建并发送受保护待APDU###################
L=len(DO97+DO8E)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
protectedAPDU=cmdheader[0:8]+L+DO97+DO8E+'00'
print 'protectedAPDU is : '+protectedAPDU.upper()
##############接收eMRTD ic的响应APDU##########################
'''
i=0;
RAPDU=raw_input('输入返回的的RAPDU:')
RAPDU=RAPDU.replace(' ', '')
'''

RAPDU = '8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000'####-------------------------------设定该值，待删除
print 'RAPDU is : '+RAPDU.upper()

##############通过计算DO87和DO99并置待MAC 验证CC`#####################
############# SSC+1 #############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #高位零不能省略 保持长度
print 'after +1 SSC is : '+SSC.upper()
###############构建DO87（从响应APDU中提取）##############
L=RAPDU[2:4]
L=eval('0x'+L)
L=L*2+4
DO87=RAPDU[0:L]
print 'DO87 is : '+DO87

############并置SSC,DO87和DO99得到K，填充在KmacDES中完成######################
K=SSC+DO87+DO99
print 'K is : '+K
#############用KSmac计算MAC################
CC1=KmacDES(K,SKa2,SKb2)
print 'CC1 is : '+CC1.upper()
##############提取DO8Er from RAPDU###################
L8799=len(DO87+DO99)#DO87 和DO99后面便是DO8E
L8E=RAPDU[L8799+2:L8799+4]
L8E=eval('0x'+L8E)
L8E=L8E*2+4
DO8Er=RAPDU[L8799+4:L8799+L8E]
print 'DO8Er is : '+DO8Er


#####################################################
print 'Is CC1 equals to DO8Er ?'
print CC1.upper()==DO8Er.upper()
#############用KSenc解密DO87###############
data1=iKencTDES(DO87[6:],SKa1,SKb1)#解密后的数据还得把填充部分去掉
a=range(len(data1))
a.reverse()
for i in a:
    if data1[i]=='0':
        continue
    elif data1[i]=='8':
        break
data1=data1[0:i]                
print '解密后的数据 data1 is : '+data1.upper()
#########获取长度########？？？？？？？？？？？？？？？？
L=data1[2:4]
L=eval('0x'+L)+2
print L
print '结构待长度 L is : '+str(L)

##################################
##################################
##################################
############# Read Binary 命令从偏移4开始剩下的18字节####################
print '################### Read Binary 命令从偏移4开始剩下的18字节####################'
###################填充命令报头######################
'''
i=0;
while(i!=8):
    cmdheader=raw_input('输入四字节命令报头:')
    cmdheader=cmdheader.replace(' ', '')
    i=len(cmdheader)
    if i!=8:
        print '输入值长度错误,请不要省略0'
    if cmdheader[0:2]!='0C':
        if cmdheader[0:2]!='0c':
            print 'CLA必须是0C'
            i=0
cmdheader=cmdheader+'80000000'#填充
'''
cmdheader='0cb0000480000000'########设定该值 待删除-----------------------------------
print 'cmdheader is : '+cmdheader.upper()
##########建立DO97################
'''
i=0;
while(i!=2):
    LE=raw_input('LE:')
    LE=LE.replace(' ', '')
    i=len(LE)
    if i!=4:
        print '输入值长度错误,请不要省略0'
DO97='9701'+LE #填充在MAC函数中完成
'''
DO97='970112'######设定该值，待删除------------------------------------------
print 'DO97 is : '+DO97.upper()
############并置cmdheader和DO97得到M######################
M=cmdheader+DO97
print 'M is ： '+M.upper()
############ SSC +1 ##################
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #高位零不能省略 保持长度
print 'after +1 SSC is : '+SSC.upper()
#############并置SSC和M，得到N（无填充，填充在KmacDes函数中完成）###################
N=SSC+M
print 'N is : '+N.upper()+'未填充，填充在KmacDes函数中完成'
CC=KmacDES(N,SKa2,SKb2)
print 'CC is ： '+CC.upper()
#############建立DO8E##################
L=len(CC)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
DO8E='8E'+L+CC
print 'DO8E is : '+DO8E.upper()

#############构建并发送受保护待APDU###################
L=len(DO97+DO8E)/2
L=hex(L)[2:]
if len(L)<2:
    L='0'+L
protectedAPDU=cmdheader[0:8]+L+DO97+DO8E+'00'
print 'protectedAPDU is : '+protectedAPDU.upper()
##############接收eMRTD ic的响应APDU##########################
'''
i=0;
RAPDU=raw_input('输入返回的的RAPDU:')
RAPDU=RAPDU.replace(' ', '')
'''

RAPDU = '871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000'####-------------------------------设定该值，待删除
print 'RAPDU is : '+RAPDU.upper()

##############通过计算DO87和DO99并置待MAC 验证CC`#####################
############# SSC+1 #############
n=len(SSC)
SSC=eval('0x'+SSC)+1
SSC=hex(SSC)[2:-1]
while len(SSC)!=n:
    SSC='0'+SSC    #高位零不能省略 保持长度
print 'after +1 SSC is : '+SSC.upper()
###############构建DO87（从响应APDU中提取）##############
L=RAPDU[2:4]
L=eval('0x'+L)
L=L*2+4
print L
DO87=RAPDU[0:L]
print 'DO87 is : '+DO87.upper()
############并置SSC,DO87和DO99得到K，填充在KmacDES中完成######################
K=SSC+DO87+DO99
print 'K is : '+K.upper()
#############用KSmac计算MAC################
CC1=KmacDES(K,SKa2,SKb2)
print 'CC1 is : '+CC1.upper()
################################################
#######提取DO8Er from RAPDU#######################################
L8799=len(DO87+DO99)#DO87 和DO99后面便是DO8E
L8E=RAPDU[L8799+2:L8799+4]
L8E=eval('0x'+L8E)
L8E=L8E*2+4
DO8Er=RAPDU[L8799+4:L8799+L8E]
print 'DO8Er is : '+DO8Er.upper()

############################################
print 'Is CC1 equals to DO8Er ?'
print CC1.upper()==DO8Er.upper()

#############用KSenc解密DO87###############

data2=iKencTDES(DO87[6:],SKa1,SKb1)#还得去掉填充部分

a=range(len(data2))
a.reverse()
for i in a:
    if data2[i]=='0':
        continue
    elif data2[i]=='8':
        break
data2=data2[0:i]                

print '解密后的数据 data2 is : '+data2.upper()



EFcom=data1+data2
print '最终结果 EF.COM is : '+EFcom.upper()





















