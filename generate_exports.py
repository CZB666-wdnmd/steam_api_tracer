"""
Generate C++ forwarding stubs + .def from steam_api64_o.dll exports.

Usage:
    python generate_exports.py steam_api64_o.dll

Output:
    steam_api64.def          - Module definition file (all exports listed)
    forwarded_exports.cpp    - C++ forwarding stubs (lazy-resolve via GetProcAddress)
"""

import subprocess
import sys
import re
import os

# Functions explicitly intercepted in the proxy .cpp (do NOT generate stubs)
INTERCEPTED_FUNCTIONS = {
    "SteamAPI_Init",
    "SteamAPI_InitSafe",
    "SteamAPI_InitFlat",
    "SteamAPI_Shutdown",
    "SteamAPI_RestartAppIfNecessary",
    "SteamAPI_RunCallbacks",
    "SteamAPI_IsSteamRunning",
    "SteamAPI_GetHSteamPipe",
    "SteamAPI_GetHSteamUser",
    "SteamInternal_CreateInterface",
    "SteamInternal_FindOrCreateUserInterface",
    "SteamInternal_FindOrCreateGameServerInterface",
    "SteamInternal_ContextInit",
    "SteamAPI_RegisterCallback",
    "SteamAPI_UnregisterCallback",
    "SteamAPI_RegisterCallResult",
    "SteamAPI_UnregisterCallResult",
}


def get_exports_dumpbin(dll_path):
    try:
        result = subprocess.run(
            ["dumpbin", "/exports", dll_path],
            capture_output=True, text=True, check=True
        )
        exports = []
        for line in result.stdout.splitlines():
            match = re.match(r'\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)', line)
            if match:
                exports.append(match.group(1))
        return exports
    except FileNotFoundError:
        return None


def get_exports_objdump(dll_path):
    try:
        result = subprocess.run(
            ["objdump", "-p", dll_path],
            capture_output=True, text=True, check=True
        )
        exports = []
        in_export = False
        for line in result.stdout.splitlines():
            if "[Ordinal/Name Pointer]" in line:
                in_export = True
                continue
            if in_export:
                match = re.match(r'\s+\[\s*\d+\]\s+(\S+)', line)
                if match:
                    exports.append(match.group(1))
                elif line.strip() == "":
                    break
        return exports
    except FileNotFoundError:
        return None


def get_exports(dll_path):
    exports = get_exports_dumpbin(dll_path)
    if exports:
        return exports
    exports = get_exports_objdump(dll_path)
    if exports:
        return exports
    print("ERROR: Neither dumpbin nor objdump found.")
    print("       Run from 'x64 Native Tools Command Prompt' or install MinGW.")
    sys.exit(1)


def generate_files(dll_path):
    print(f"Reading exports from: {dll_path}")
    all_exports = get_exports(dll_path)

    if not all_exports:
        print("ERROR: No exports found!")
        sys.exit(1)

    print(f"Total exports found: {len(all_exports)}")

    intercepted = []
    forwarded = []
    # Separate data exports (lowercase 'g_' prefix globals) vs function exports
    forwarded_funcs = []
    forwarded_data = []

    for name in all_exports:
        if name in INTERCEPTED_FUNCTIONS:
            intercepted.append(name)
        else:
            forwarded.append(name)
            # Heuristic: g_pSteamXxx / g_xxx are data exports
            if name.startswith("g_"):
                forwarded_data.append(name)
            else:
                forwarded_funcs.append(name)

    print(f"Intercepted (in proxy .cpp): {len(intercepted)}")
    print(f"Forwarded functions:         {len(forwarded_funcs)}")
    print(f"Forwarded data symbols:      {len(forwarded_data)}")

    # ---- Generate .def ----
    with open("steam_api64.def", "w") as f:
        f.write("LIBRARY \"steam_api64\"\n")
        f.write("EXPORTS\n")

        f.write("\n    ; === Intercepted by proxy (defined in steam_api_proxy.cpp) ===\n")
        for name in sorted(intercepted):
            f.write(f"    {name}\n")

        f.write("\n    ; === Forwarded functions (defined in forwarded_exports.cpp) ===\n")
        for name in sorted(forwarded_funcs):
            f.write(f"    {name}\n")

        f.write("\n    ; === Forwarded data symbols (defined in forwarded_exports.cpp) ===\n")
        for name in sorted(forwarded_data):
            f.write(f"    {name} DATA\n")

    print(f"Generated: steam_api64.def")

    # ---- Generate forwarded_exports.cpp ----
    with open("forwarded_exports.cpp", "w") as f:
        f.write("// Auto-generated forwarding stubs for steam_api64 proxy\n")
        f.write("// DO NOT EDIT - regenerate with: python generate_exports.py steam_api64_o.dll\n")
        f.write(f"// Total forwarded: {len(forwarded)} "
                f"({len(forwarded_funcs)} functions, {len(forwarded_data)} data)\n\n")

        f.write("#define WIN32_LEAN_AND_MEAN\n")
        f.write("#include <windows.h>\n")
        f.write("#include <cstdio>\n\n")

        f.write("// ---- Original DLL handle (set by proxy DllMain) ----\n")
        f.write("// Defined in steam_api_proxy.cpp\n")
        f.write("extern HMODULE g_OriginalDll;\n\n")

        f.write("// ---- Cached function pointers ----\n")
        f.write("namespace {\n\n")

        # One cached pointer per forwarded function
        for name in forwarded_funcs:
            f.write(f"    static void* cached_{name} = nullptr;\n")

        f.write("\n")

        # One cached pointer per data export
        for name in forwarded_data:
            f.write(f"    static void* cached_{name} = nullptr;\n")

        f.write("\n")

        # Helper to resolve
        f.write("    static void* Resolve(const char* name, void*& cache)\n")
        f.write("    {\n")
        f.write("        void* p = cache;\n")
        f.write("        if (p) return p;\n")
        f.write("        p = (void*)GetProcAddress(g_OriginalDll, name);\n")
        f.write("        if (p) cache = p;\n")
        f.write("        return p;\n")
        f.write("    }\n\n")
        f.write("} // anonymous namespace\n\n")

        # ---- Generate function forwarding stubs ----
        # Strategy: each stub is a naked-like function that resolves & jumps.
        # In MSVC x64 we cannot use __declspec(naked), so we use an indirect
        # call through a function pointer.  The stub takes no declared params
        # and returns void* -- the caller's registers are preserved because
        # the stub immediately tail-calls the resolved pointer with the same
        # calling convention (all args still in rcx/rdx/r8/r9/stack).
        #
        # We use a #pragma comment(linker) trick:  export the stub with the
        # original name.  Actually, since we're using a .def file, we just
        # need the symbol to exist with the right name.
        #
        # For x64 Microsoft ABI, a varargs-style "void* func()" declaration
        # generates a function whose prologue doesn't touch RCX/RDX/R8/R9 if
        # compiled with /O2 (no frame pointer, no local saves).  But that's
        # fragile.  Instead, we use inline assembly via an intermediate approach:
        #
        # The MOST RELIABLE method on MSVC x64 without ASM is:
        #   - Resolve the target pointer
        #   - Use a volatile function-pointer call  (the compiler will do a
        #     CALL not JMP, adding stack frame overhead, but it's correct)
        #
        # However for a true zero-overhead forward we need ASM.  Let's generate
        # a tiny MASM file per the original approach - but fully automated.

        # Actually, the simplest correct solution: generate MASM again, it's
        # one .asm file, fully auto-generated, no hand-writing needed.

    # Overwrite: generate .asm instead
    os.remove("forwarded_exports.cpp")

    # ---- Generate .asm (MASM x64) ----
    with open("forwarded_exports.asm", "w") as f:
        f.write("; Auto-generated forwarding thunks for steam_api64 proxy\n")
        f.write("; DO NOT EDIT - regenerate with: python generate_exports.py\n\n")
        f.write("; Uses g_OriginalDll (set by DllMain in steam_api_proxy.cpp)\n")
        f.write("EXTERN g_OriginalDll:QWORD\n\n")
        f.write("; Import GetProcAddress via IAT\n")
        f.write("EXTERN __imp_GetProcAddress:QWORD\n\n")

        f.write(".data\n\n")

        # Cached pointers
        for name in forwarded_funcs:
            f.write(f"    cached_{name} QWORD 0\n")

        f.write("\n")

        # String table
        for name in forwarded_funcs:
            f.write(f'    sz_{name} DB "{name}", 0\n')

        # Data exports: we need to expose a pointer that points into the
        # original DLL's data.  We'll create a QWORD for each and fill them
        # at init time from C++ side.
        if forwarded_data:
            f.write("\n    ; Data export pointers (resolved by C++ init code)\n")
            f.write("    PUBLIC g_NumForwardedData\n")
            f.write(f"    g_NumForwardedData DWORD {len(forwarded_data)}\n\n")

            for name in forwarded_data:
                f.write(f"    PUBLIC {name}\n")
                f.write(f"    {name} QWORD 0\n")

        f.write("\n.code\n\n")

        # Function thunks
        for name in forwarded_funcs:
            f.write(f"; ---- {name} ----\n")
            f.write(f"{name} PROC\n")
            f.write(f"    mov     rax, [cached_{name}]\n")
            f.write(f"    test    rax, rax\n")
            f.write(f"    jz      resolve_{name}\n")
            f.write(f"    jmp     rax\n")
            f.write(f"resolve_{name}:\n")
            # Save all arg registers (Microsoft x64 ABI)
            f.write(f"    ; Save volatile arg registers\n")
            f.write(f"    push    rcx\n")
            f.write(f"    push    rdx\n")
            f.write(f"    push    r8\n")
            f.write(f"    push    r9\n")
            f.write(f"    sub     rsp, 28h          ; shadow space + alignment\n")
            f.write(f"    mov     rcx, [g_OriginalDll]\n")
            f.write(f"    lea     rdx, [sz_{name}]\n")
            f.write(f"    call    QWORD PTR [__imp_GetProcAddress]\n")
            f.write(f"    mov     [cached_{name}], rax\n")
            f.write(f"    add     rsp, 28h\n")
            f.write(f"    pop     r9\n")
            f.write(f"    pop     r8\n")
            f.write(f"    pop     rdx\n")
            f.write(f"    pop     rcx\n")
            f.write(f"    test    rax, rax\n")
            f.write(f"    jz      fail_{name}\n")
            f.write(f"    jmp     rax\n")
            f.write(f"fail_{name}:\n")
            f.write(f"    xor     eax, eax\n")
            f.write(f"    ret\n")
            f.write(f"{name} ENDP\n\n")

        f.write("END\n")

    print(f"Generated: forwarded_exports.asm")

    # ---- Generate data_exports.h (for C++ init) ----
    if forwarded_data:
        with open("data_exports.h", "w") as f:
            f.write("// Auto-generated - data export list for runtime resolution\n")
            f.write("// DO NOT EDIT\n")
            f.write("#pragma once\n\n")

            f.write("// Declare the ASM-defined data symbols\n")
            f.write("extern \"C\" {\n")
            for name in forwarded_data:
                f.write(f"    extern void* {name};\n")
            f.write("}\n\n")

            f.write("// Table for batch resolution\n")
            f.write("struct DataExportEntry {\n")
            f.write("    const char* name;\n")
            f.write("    void**      pSlot;\n")
            f.write("};\n\n")

            f.write("static const DataExportEntry g_DataExports[] = {\n")
            for name in forwarded_data:
                f.write(f'    {{ "{name}", &{name} }},\n')
            f.write("};\n\n")

            f.write(f"static const int g_NumDataExports = {len(forwarded_data)};\n")

        print(f"Generated: data_exports.h")
    else:
        # Write empty header
        with open("data_exports.h", "w") as f:
            f.write("// Auto-generated - no data exports\n")
            f.write("#pragma once\n")
            f.write("struct DataExportEntry { const char* name; void** pSlot; };\n")
            f.write("static const DataExportEntry g_DataExports[] = {};\n")
            f.write("static const int g_NumDataExports = 0;\n")
        print(f"Generated: data_exports.h (empty)")

    print(f"\nDone! Now rebuild with build_msvc.bat")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <path_to_steam_api64_o.dll>")
        sys.exit(1)

    dll_path = sys.argv[1]
    if not os.path.exists(dll_path):
        print(f"ERROR: File not found: {dll_path}")
        sys.exit(1)

    generate_files(dll_path)