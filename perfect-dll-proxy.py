import pefile
import argparse
import os
import sys

"""
References:
- https://nibblestew.blogspot.com/2019/05/
- https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
- https://learn.microsoft.com/en-us/cpp/build/reference/export-exports-a-function
- https://devblogs.microsoft.com/oldnewthing/20121116-00/?p=6073
- https://medium.com/@lsecqt/weaponizing-dll-hijacking-via-dll-proxying-3983a8249de0
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking
- https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence
- https://github.com/Flangvik/SharpDllProxy
- https://github.com/hfiref0x/WinObjEx64
"""

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Generate a proxy DLL")
    parser.add_argument("dll", help="Path to the DLL to generate a proxy for")
    parser.add_argument("--output", "-o", help="Generated C++ proxy file to write to")
    parser.add_argument("--force-ordinals", "-v", action="store_true", help="Force matching ordinals")
    args = parser.parse_args()
    dll: str = args.dll
    output: str = args.output
    basename = os.path.basename(dll)
    if output is None:
        file, _ = os.path.splitext(basename)
        output = f"{file}.cpp"

    # Use the system directory if the DLL is not found
    if not os.path.exists(dll) and not os.path.isabs(dll):
        dll = os.path.join(os.environ["SystemRoot"], "System32", dll)
    if not os.path.exists(dll):
        print(f"File not found: {dll}")
        sys.exit(1)

    # Enumerate the exports
    pe = pefile.PE(dll)
    commands = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = exp.ordinal
        if exp.name is None:
            command = f"__proxy{ordinal}=\" DLLPATH \".#{ordinal},@{ordinal},NONAME"
        else:
            name = exp.name.decode()
            command = f"{name}=\" DLLPATH \".{name}"
            # The first underscore is removed by the linker
            if name.startswith("_"):
                command = f"_{command}"
            # Special case for COM exports
            if name in {
                "DllCanUnloadNow",
                "DllGetClassObject",
                "DllInstall",
                "DllRegisterServer",
                "DllUnregisterServer",
                }:
                command += ",PRIVATE"
            elif args.force_ordinals:
                command += f",@{ordinal}"
        commands.append(command)

    # Generate the proxy
    with open(output, "w") as f:
        f.write(f"""#include <Windows.h>

#ifdef _WIN64
#define DLLPATH "\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}"
#else
#define DLLPATH "\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}"
#endif // _WIN64

""")
        for command in commands:
            f.write(f"#pragma comment(linker, \"/EXPORT:{command}\")\n")
        f.write("""
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
""")


if __name__ == "__main__":
    main()