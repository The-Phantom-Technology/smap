#!/usr/bin/python

# smap - shellcode mapper
#    Copyright (C) <2016>  <M U Suraj>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Created by suraj (#r00t)

__author__ = "suraj (#r00t)"
__blog__   = "www.r00tl4b.wordpress.com"
__license__ = "GNU-GPLv3"

import sys
import os
from subprocess import *
from core import pycolor
from argparse import *
import re
import time

#global vars
pyc = pycolor.pyColor()
SCBYTE = r'\\x[0-9a-fA-F]{2}'

def ParseArgs():
	
	parser = ArgumentParser(description='smap - shellcode mapper')
	parser.add_argument('-a','--architecture',\
				type=str,\
				help="Specify architecture",\
				default='i386')
	parser.add_argument('-sf','--syntax-format',\
				type=str,\
				help="Disassembly syntax format. AT&T/intel",\
				default='intel')
	parser.add_argument('-f','--file',\
				required=True, type=str,\
				help="File which contains shellcode")
	args = parser.parse_args()
	return args

def Banner():
	print ('''
                                            
                                            
  /$$$$$$$ /$$$$$$/$$$$   /$$$$$$   /$$$$$$ 
 /$$_____/| $$_  $$_  $$ |____  $$ /$$__  $$
|  $$$$$$ | $$ \ $$ \ $$  /$$$$$$$| $$  \ $$
 \____  $$| $$ | $$ | $$ /$$__  $$| $$  | $$
 /$$$$$$$/| $$ | $$ | $$|  $$$$$$$| $$$$$$$/
|_______/ |__/ |__/ |__/ \_______/| $$____/ 
                                  | $$  
          Shellcode Mapper        | $$       
      %s    |__/    
	
				
				''')%(pyc.Fore('red')+pyc.Style('ul')+'Created by suraj (#r00t)'+pyc.Style('normal'))
	print (pyc.Info("Started smap at "+time.strftime('%X')))

def SCbyteFind(BUFFER):
	sc_op_found = re.findall(SCBYTE, BUFFER)
	buf_arr = []
	for op in sc_op_found:
		xc = int(op[2:], 16)
		buf_arr.append(xc)
	return buf_arr	

def stageOP(buf_arr):
	byte_arr = set()
	for byte in buf_arr:
		byte_arr.add(byte)
	entire_arr = ""
	print("\t-> Unique charset=%s%d chars%s")%(pyc.Fore("blue"),len(byte_arr),pyc.Style("normal"))
	sys.stdout.write("\t\top codes: %s"%(pyc.Fore('yellow')))
	byte_arr=sorted(byte_arr)
	for each_op in byte_arr:
		sys.stdout.write("%02x "%(each_op)) 
	sys.stdout.write(pyc.Style('normal'))

	print("%s")%(pyc.Fore("yellow")+entire_arr+pyc.Style("normal"))

def getOPcodes(fname):
	print(pyc.Info("Checking file(%s).."%(fname)))
	fileStat = False
	if os.path.isfile(fname):
		if os.access(fname, os.R_OK):
			print(pyc.Succ("File %s OK")%(fname))
			fileStat = True
		else:
			print(pyc.Err("Check the permissions"))
			sys.exit()
	else:
		print(pyc.Err("File(%s) doesnt exist"%(fname)))
		sys.exit()
	
	if fileStat:
		fhandle = open(fname)
		BUFFER = fhandle.read()
		buf_arr = SCbyteFind(BUFFER)
		fhandle.close()
	print(pyc.Info(pyc.Imp("Details")))
	print("\t-> Length=%s%d byte(s)%s")%(pyc.Fore("blue"),len(buf_arr),pyc.Style("normal"))
	return buf_arr

def createBYTEARR(buf_arr):
	byteArrFile='tmp/output.tmp'
	byte_arr = bytearray(buf_arr)
	fhandle = open(byteArrFile, 'wb')
	fhandle.write(byte_arr)
	fhandle.close()
	return byteArrFile

def checkSyntax(syntax):
	if(syntax.lower()=="at&t"):return "AT&T"
	else:return "intel"

def parseOutput(output):
	WL = re.findall(r'\s?[0-9a-f]*:\s[0-9a-f]{2}.*', output)
	TL = []
	for each in WL:TL.append(each)
	return TL

def has_Instruction(disassemblyStr,keyword):
	disassemblyStr = ' '.join(disassemblyStr)
	if(keyword in disassemblyStr):
		return True
	else:
		return False

def AfterDis(totBC, totACS):
	totBC2 = []
	print("")
	print(pyc.Info(pyc.Imp("Summary")))
	for i in totBC:
		try:
			for b in (i.split(',')):
				totBC2.append(b)
		except:totBC2.append(i)
	print("\t-> Bad-char count=%s%d char(s)%s")%(pyc.Fore('yellow'),len(totBC2),pyc.Style('normal'))
	print("\t-> Ascii count=%s%d char(s)%s")%(pyc.Fore('blue'),len(totACS),pyc.Style('normal'))
	totACS = ''.join(totACS)
	print("\t   (%s%s%s)")%(pyc.Fore('red'),totACS,pyc.Style('normal'))
	print(""+pyc.Info("Task completed\n"))

def SCAnalyser(line):
	line = line[1].strip(" ").split(" ")
	bad_chrs = ['00','0a','0d','09','0c']
	ascii = badchr = "op: "
	for op in line:
		if op in bad_chrs:
			badchr+="%s "%(op)
		if ((int(op,16)>=0x20)and(int(op,16)<0x7f)):
			ascii+=chr(int(op,16))
		else:
			ascii+='.'
	return(badchr[3:],ascii[3:])

def prettyPrint(disData):
	OPcolor = {'j ':'purple',\
			'jmp':'blue',\
			'jn':'purple',\
			'jae':'purple',\
			'push':'green',\
			'pop':'green',\
			'xor':'grey',\
			'bad':'bg_red',\
			'call':'lightblue',\
			'int':'red',\
			'nop':'bg_grey',\
			'mov':'yellow'}
	
	prettyline = color = ''
	totBC = []
	totACS = []
	for line in disData:
		badch = ascii = ''
		bc, asc = SCAnalyser(line)
		try:
			color = OPcolor[line[2].split(' ')[0]]
		except:	color = ''
		if color!='':
			prettyline = (line[0].center(8,' ') + pyc.Fore(color) + line[1].center(16,' ') + asc.center(16,' ') + '\t' + line[2] + pyc.Style('normal') + ' '*(32-len(line[2]))) 
		else:
			prettyline = (line[0].center(8,' ') + line[1].center(16,' ') + asc.center(16,' ') + '\t' + line[2] + ' '*(28-len(line[2]))) 

		bc=filter(None, set(bc.split(" ")))
		if(len(bc)!=0):
			badch = "(Possible bad char : %s%s%s)"%(pyc.Fore('yellow'),', '.join(bc),pyc.Style('normal'))
			prettyline+=badch
		else:pass
		if len(bc)!=0:
			totBC.append(', '.join(bc))

		asc=asc.replace('.','')
		totACS.append(asc)
		if asc!=" ":
			prettyline+="(Char : %s\"%s\"%s)"%(pyc.Fore('blue'),asc[1:],pyc.Style('normal'))
		print(prettyline)

	return(totBC, totACS)		


def disassemble(fname, arch, syntax):
	disData = []
	print(pyc.Info(pyc.Imp("Disassembly info")))
	print("\t-> File name=%s%s%s")%(pyc.Fore("blue"),fname.split('/')[1],pyc.Style("normal"))
	print("\t-> Architecture=%s%s%s")%(pyc.Fore("blue"),arch,pyc.Style("normal"))
	print("\t-> Syntax=%s%s%s")%(pyc.Fore("blue"),syntax,pyc.Style("normal"))
	if(syntax=="AT&T"):
		cmdArg = ['objdump','-D','-b','binary','-m',arch,fname]
	else:
		cmdArg = ['objdump','-D','-b','binary','-m',arch,'-M','intel',fname]
	
	Fsections = Popen(['objdump','-h','-b','binary',fname], stdout=PIPE, stderr=PIPE)
	sectionOut, sectionErr = Fsections.communicate()
	if sectionErr:pass
	else:sectionOut = re.findall(r'\.\w+\s',sectionOut)
	print("\t-> Sections count=%s%d%s")%(pyc.Fore("blue"),len(sectionOut),pyc.Style("normal"))
	sectionsT = []
	for section in sectionOut:
		sectionsT.append(section)
	print('\t\tSection(s): '+(','.join(sectionsT)))

	objdmpPopen = Popen(cmdArg, stdout=PIPE, stderr=PIPE)
	objOut, objErr = objdmpPopen.communicate()
	if objErr:
		print(pyc.Err("Error: %s"%(objErr)))
		sys.exit(0)
	for i in parseOutput(objOut): 
		disData.append(i.split("\t"))

	print(pyc.Succ("Disassembly complete")+" (Format : Offset(0), OP-Codes, Hex-dump, Instructions, Analysis)")
	print("")
	return disData
	
	
if __name__ == '__main__':
	try:
		Banner()
		args = ParseArgs()	
		buf_arr = getOPcodes(args.file)
		stageOP(buf_arr)
		byteArrFile = createBYTEARR(buf_arr)
		syntax = checkSyntax(args.syntax_format)
		disData=disassemble(byteArrFile, args.architecture, syntax)
		totBC, totACS = prettyPrint(disData)
		AfterDis(totBC, totACS)
	except Exception, ex:
		#print pyc.Err("Exception('%s') occured\n\t%s-> Errno : %d\n\t-> Error : %s")%(type(ex).__name__,pyc.Fore('grey'),ex.args[0],ex.args[1])
		print(pyc.Err("Error : %s%s%s"%(pyc.Fore('grey'), str(ex), pyc.Style('normal'))))
		
