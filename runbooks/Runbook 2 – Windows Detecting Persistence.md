## 🪟 **Runbook 2 – Windows: Detecting Malware Persistence**

**Objective**
Discover Windows persistence via registry, Scheduled Tasks, WMI, services, startup folders.

**Tools Required**
Sysinternals: **Autoruns**, `Process Explorer`; native: `reg`, `schtasks`, PowerShell/WMI

**Download Links**

* **Autoruns**: download from official Sysinternals site ([Microsoft Learn][2], [Microsoft Learn][3], [Reddit][4])
* **Process Explorer** (part of Sysinternals Suite) ([Microsoft Learn][5], [Reddit][4])

**Step-by-Step Instructions**

1. **Autoruns scan**

   ```powershell
   autoruns.exe /accepteula /nologo /output autoruns.csv
   ```

   → Inspect entries under *Logon*, *Scheduled Tasks*, *Services*.

2. **Registry Run keys**

   ```cmd
   reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
   reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   ```

   → EXEs in user-temp paths or unknown filenames.

3. **Startup folders**

   ```powershell
   dir "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
   ```

   → Unexpected .lnk or script files.

4. **Scheduled Tasks**

   ```cmd
   schtasks /query /fo LIST /v
   ```

   → Tasks using PowerShell or scripts with Base64 / encoded commands.

5. **WMI persistence**

   ```powershell
   Get-WmiObject -Namespace root\subscription -Class __EventFilter
   Get-WmiObject -Namespace root\subscription -Class __EventConsumer
   Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
   ```

   → Suspicious filters or consumers causing code execution.

6. **Service-based persistence**

   ```cmd
   sc query type= service
   ```

   → Services installed by non-admin contexts or pointing to temp folder binaries.

**What to Look For / IOCs**

* Autoruns entries in `Run` keys from temp/user directories.
* Unknown scheduled tasks with obfuscated arguments.
* WMI event subscriptions not created by admins.
* Services installed with no digital signature or odd paths.


