# Validation and release context: dll-resolution-explainer 1.0.0

Development/build validation: Windows Server 2025 x64. The exact executable completed physical Windows 11 Pro 25H2 x64 qualification (build 26200.9550) and Windows 10 Pro 22H2 x64 qualification in a dedicated QEMU VM (build 19045.6466). Physical Windows 10 hardware and ARM64 were not qualified. Windows 11 completion is user supplied with retained raw results; the consolidated report is unavailable. Historical Windows 10 detailed ledgers are unavailable; completion is user supplied.

The final ZIP was assembled after executable qualification around the unchanged qualified EXE. Execution of this final assembled package on Windows is not claimed. Development validation is distinct from client qualification.

Qualified executable SHA-256: `e24a0e8b3c2ea453ebd4247ca06d0d853cfd935b089d23ccff0c4a538fa0d52b`.

Microsoft Visual C++ x64 Redistributable is required where its runtime libraries are absent.

See application documentation for query, output and safety limits. Windows may perform internal activity while servicing read-only API calls.
