with open("./inode_0x8befcbfc5908.dmp", "rb") as f: # or shell
 print(f.seek(0x3020))
 data = f.read(0x67ec0)
 print(data)
with open("./extracted_module", "wb") as f:
 f.write(data)
