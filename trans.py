
D='239ab9cb282daf66231dc5a4df6bfbae00000001'
D=list(D)
DD=[0]*(len(D)/2)
for i in range(len(D)/2):   
    print i
    DD[i]='\\x'+D[2*i]+D[2*i+1]
