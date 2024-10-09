# Perfect DLL Proxy

A while ago I needed a proxy to perform DLL hijacking, but I did not like how existing solutions generated ASM stubs to deal with the forwarding. It turns out that there is a trick to get forwards to work with an absolute path:

```cpp
#pragma comment(linker,
"/EXPORT:CredPackAuthenticationBufferA=\\\\.\\GLOBALROOT\\SystemRoot\\System32\\credui.dll.CredPackAuthenticationBufferA"
)
```

See the references for more information.

To automatically generate a DLL that exports everything and loads an arbitrary DLL (without intercepting functions), look at the following project: https://github.com/namazso/dll-proxy-generator

## Usage

```sh
python -m pip install pefile
python perfect-dll-proxy.py credui.dll
```

## References

- https://nibblestew.blogspot.com/2019/05/
- https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
- https://learn.microsoft.com/en-us/cpp/build/reference/export-exports-a-function
- https://devblogs.microsoft.com/oldnewthing/20121116-00/?p=6073
- https://medium.com/@lsecqt/weaponizing-dll-hijacking-via-dll-proxying-3983a8249de0
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking
- https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence
- https://github.com/Flangvik/SharpDllProxy
- https://github.com/hfiref0x/WinObjEx64
