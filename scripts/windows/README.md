\# Malware Detection and Forensic Triage Script



\*\*Purpose\*\*: Comprehensive system analysis for CTF and incident response  

\*\*Author\*\*: Senior Cybersecurity Engineer  

\*\*Version\*\*: 1.0



---



\## Configuration Variables

\- Create output directory

\- Initialize report file



---



\## SECTION 1: SYSTEM INFORMATION GATHERING



---



\## SECTION 2: RUNNING PROCESSES ANALYSIS



\- Get detailed process information

\- Check for suspicious process names (common malware names)

\- Look for processes with suspicious characteristics using Sysinternals  

&nbsp; Example:  

&nbsp;---



\## SECTION 3: NETWORK CONNECTIONS ANALYSIS



\- Look for suspicious connections



---



\## SECTION 4: REGISTRY PERSISTENCE MECHANISMS



\- Check common autorun locations

\- HKLM Run keys

\- HKCU Run keys

\- Check Winlogon key

\- Check Image File Execution Options (IFEO)



---



\## SECTION 5: SCHEDULED TASKS ANALYSIS



\- Export all scheduled tasks

\- Look for suspicious tasks



---



\## SECTION 6: SERVICES ANALYSIS



\- Export service information

\- Look for non-Microsoft services using Sysinternals or native tools



---



\## SECTION 7: STARTUP FOLDERS ANALYSIS



\- Check common startup folders



---



\## SECTION 8: PROCESS INJECTION DETECTION



\- Check for DLL injection indicators

\- Use `tasklist` to show modules (DLLs) loaded in processes

\- Look for unsigned or suspicious DLLs in critical processes



---



\## SECTION 9: FILE SYSTEM ANALYSIS



\- Check for files in temporary directories

\- Check Windows directory for suspicious files

\- Check System32 for recently modified files



---



\## SECTION 10: EVENT LOG ANALYSIS (if available)



\- Check for recent logon events

\- Check for process creation events (if auditing enabled)



---



\## SECTION 11: SYSINTERNALS TOOLS (if available)



\- Autoruns analysis

\- Handle analysis

\- ListDLLs analysis for process injection detection

\- pslist64 for detailed process analysis



---



\## SECTION 12: SUMMARY AND RECOMMENDATIONS



---



\## CLEANUP AND COMPLETION



---



\## HELPER FUNCTIONS



