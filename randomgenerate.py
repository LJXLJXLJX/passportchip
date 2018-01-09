import random
def randomgenerate(bytesnum):
    a=[0]*bytesnum
    for i in range(bytesnum):
        a[i]=random.randint(0,255)
        a[i]=hex(a[i])[2:]
        if len(a[i])!=2:
            a[i]='0'+a[i]
    a=''.join(a)
    return a
