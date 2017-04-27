def pow (a,b,c):
	if(b==0):
		return 1
	tmp=pow(a,b/2,c)
	if (b%2==1):
		return (a*tmp*tmp)%c
	else:
		return (tmp*tmp)%c

print (pow(8,5,5))

a=8%5
i=5
b=1
while(True):
	t=i%2
	i=i/2
	if(t==1):
		b=(a*b)%5
	if(i==0):
		break
	a=(a*a)%5	

print(b)
