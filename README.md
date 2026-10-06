# dll-resolution-explainer 1.0.0

> Runtime prerequisite for the exact qualified EXE: Microsoft Visual C++ x64 Redistributable is required when the imported runtime DLLs are absent. This supersedes any static-CRT/no-redistributable description of a source build below.


> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A native Windows command-line diagnostic for the direct DLL imports of one PE executable or DLL. It reads files as bytes, checks their structure, and explains local candidates. It never executes the inspected image, maps it as executable memory, or loads its dependencies.

```text
dll-resolution-explainer app.exe
dll-resolution-explainer --json "C:\診断\app.exe"
dll-resolution-explainer --dependency example.dll app.exe
dll-resolution-explainer --help
dll-resolution-explainer --version
```

Normal imports describe modules needed by the image's import table. Delay imports describe modules that may be needed later through delay-load machinery; they need not be used during a particular run. The tool reports module names, not imported functions, and does not recursively inspect dependency trees. Candidates are parsed without calling their entry points.

## Static resolution model

`local-static-v1` models ordinary unpackaged desktop images on the **current machine**. It enumerates these locations in order, without choosing a runtime winner:

1. Target parent directory, assumed to be the application directory. For a DLL target, the hosting EXE's directory is unknown; this assumption may not match the host.
2. Architecture-specific Windows system directory, only where the model can identify it reliably.
3. Windows directory obtained through the Windows directory API.

PATH is excluded, including the auditor's PATH. The auditor's current directory is used only to interpret a relative input path; it is never added as a dependency search location. Target runtime CWD is unknown. Legacy 16-bit system search is excluded. No command modifies PATH, DLLs, Registry configuration, manifests or installed software.

Each candidate records `present`, `absent`, or `unavailable_or_invalid`; access denial, unsafe paths and malformed candidates are uncertainty, not absence. A whole candidate PE is checked before its machine value is accepted. `machine_match` does not establish ABI, exports, runtime version or binary compatibility. ARM64EC/interoperability decisions are not reproduced; differing machine values are conservative warnings, not universal incompatibility proof.

Resolution labels are `candidate_under_model`, `multiple_candidates`, `missing_under_model`, `runtime_dependent`, `api_set_contract`, and `known_system_mechanism`. Missing means no candidate was found in the modeled locations, not that Windows cannot resolve it. KnownDLL findings retain local candidate evidence, including duplicate files, without implying those files override the mechanism.

**dll-resolution-explainer does not emulate every runtime decision of the Windows loader and does not prove which DLL an arbitrary future process will load when runtime loader state is unknown.**

Loader flags, already loaded modules, DLL redirection, `SetDefaultDllDirectories`, `SetDllDirectory`, `AddDllDirectory`, package graphs, activation contexts, launch method and runtime process state can change actual behavior. See Microsoft's [DLL search order documentation](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order).

## Windows mechanisms and architecture

Names starting with `api-ms-` or `ext-ms-` (case insensitive) are classified as API-set contract patterns. They are resolved through Windows loader mechanisms rather than ordinary same-name file searches; pattern recognition does not prove that a particular contract exists on this OS. No undocumented API-set schema is read and no host DLL mapping is guessed.

KnownDLL classification comes from read-only `REG_SZ` values in the local native Registry view of `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`. This is configuration evidence, not an inspection of active object-manager sections. It does not prove architecture-specific/WOW64 namespace membership or exact runtime selection. The tool never changes the Registry.

On an x64 host, x64 inspection models `System32` for x64 targets and `SysWOW64` for x86 targets. A 32-bit inspector on x64 models `SysWOW64` for x86 targets and omits a system directory for x64 targets. Its read operation briefly disables thread-local WOW64 filesystem redirection, restoring it with RAII, so an explicitly supplied System32 file is inspected in the native filesystem view. Other cross-architecture system paths are omitted with a warning. On a native ARM64 host, an ARM64 target inspected by a 64-bit tool can use native System32; x86/x64 emulation and ARM64EC system paths remain uncertain. Metadata parsing supports PE32 and PE32+, x86, x64, ARM64, ARM64EC, ARM32 and unknown machine values. ARM platforms have not been executed in validation.

The root resource table is inspected for manifest type 24. An adjacent `<target>.manifest` is checked with the same safe local-file policy. Contents and assembly bindings are not interpreted. Manifest presence flags SxS/activation-context limitations; absence does not rule out activation contexts supplied by a host. This is not an SxS loader implementation.

## File access and safety

No target code, DllMain, TLS callback or imported function is invoked. Production code uses `CreateFileW`/`ReadFile` and contains no target-loading, process-launching, download, symbol-server, socket or shell APIs. It does not rely on `DONT_RESOLVE_DLL_REFERENCES`.

Before opening a target or candidate, the tool rejects UNC, rooted/device namespaces, alternate data streams, remote/unknown drives and DOS device names. Only fixed, removable and RAM-disk local drives are allowed. Each ancestor and the final component are opened with `FILE_FLAG_OPEN_REPARSE_POINT`, checked, and held without write/delete sharing while reading. Every reparse point, including local junctions and symlinks, is rejected. Unsafe candidates are reported rather than followed. This conservative policy can reject legitimate OneDrive placeholders, junction-based installations or files held by writers. Local filesystem/OS integrity is trusted; this is not a security boundary against a privileged process modifying the machine.

The production application intentionally performs no network communication, DNS, SMB probes, HTTP requests, package searches or update checking. It does not enumerate PATH or remote shares. Build and test tools are separate from the production application; the optional integration test uses PowerShell, but the application does not require it.

File inspection is capped at 512 MiB, sections at 96, directory entries at 16, module imports at 4096, import names at 4096 bytes and import directory extents at 16 MiB. Headers, section extents, raw/virtual overlaps, directory mappings and descriptor/name termination are bounds checked. Unsupported or malformed inputs produce controlled errors. The parser validates import descriptor address-table mapping but does not walk every imported function/thunk. This is deliberately not a complete PE conformance verifier.

## JSON contract

`--json` emits one JSON document to stdout, with no progress text. Success documents have `schema_version: "1.0"` and `tool_version: "1.0.0"`, `target`, `imports`, `delay_imports`, `resolution_model`, `warnings` and `limitations`. Module entries contain their stored `name`, `kind`, `classification`, `resolution`, `findings` and `candidates`. Candidate fields include `path`, `status`, `architecture`, `architecture_check` and `warning`. Paths are Unicode UTF-8. Import names are raw PE bytes represented one-for-one as JSON characters U+0000–U+00FF; ASCII names retain their exact spelling. Unsafe/non-ASCII names are reported but not probed.

Errors use `schema_version`, `tool_version` when available, and `error`; there is no partial success result. Consumers should branch on `error` and ignore unknown additive fields. Exit 0 means inspection completed, even with findings; 1 means an error, and 2 means no target was supplied. `--help` and `--version` are standalone text modes. The schema is in [docs/schema.json](docs/schema.json).

## Build and test

Windows 10, Windows 11 and corresponding supported Windows Server generations are intended platforms. Primary tested host: Windows Server 2025 x64. Build with CMake 3.24+, MSVC with C++17 support and a Windows 10/11 SDK, from a Developer Command Prompt:

```bat
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
cmake --install build/release --prefix build/install
```

The runtime uses the MSVC CRT; deploy with the corresponding installed Microsoft Visual C++ runtime. No runtime installer or downloader is included. The local `scripts/build.cmd` helper is pinned to this validation machine's VS installation; use the generic commands above elsewhere. x86 builds require the x86 Developer Command Prompt and a separate build directory. `/W4`, `/permissive-` and Unicode are enabled by default. Configure `-DDRE_ANALYZE=ON` for `/analyze`, or `-DDRE_ASAN=ON` with RelWithDebInfo for MSVC ASan. ASan builds copy the installed compiler's ASan runtime beside test binaries where available; ASan is not part of the Release distribution.

CTest builds controlled normal/delay-import fixture binaries but never executes them. Parser tests include PE32/PE32+, embedded manifests, invalid RVAs, section overlaps, malformed delay descriptors, all 1024 truncations of a fixture and 20,000 deterministic mutations. If `pwsh` is available, CTest also checks JSON independently, Unicode, local candidates, missing imports, duplicates, API-set patterns, manifests and UNC/device/reparse rejection, plus read-only inspection of Windows files. Cross-architecture mismatch testing uses the optional `-X86Dependency` parameter to `tests/integration.ps1` after an x86 fixture build.

See [VALIDATION.md](VALIDATION.md) for actual results and platform coverage. MIT licensed.
