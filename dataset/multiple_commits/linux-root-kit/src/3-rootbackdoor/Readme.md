Now we want to use out kernelmodule as a backdoor to get `root` as any use on the box. We do this by hooking the syskill function and listening for a kill signal that is not used.

https://syscalls64.paolostivanin.com/


Some modifications because kernel changes

https://medium.com/@_._.._/mkdir-api-hook-a-pathway-to-an-lkm-rootkit-in-linux-ae5e3fa6d4b8