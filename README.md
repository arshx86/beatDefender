# beatDefender
Windows 11/10 script to remove windows defender

## Note
This is not **disable** script. It will remove **Virus & Threat Protection** and **antimalware service executable** completely.

## Warning
Deleting windows defender may put your system to risk, do at your own risk. There won't be a way to re-install it without clean setup.

### Before Process
**Virus & Threat Protection and defender services** are working.
![image](https://github.com/user-attachments/assets/6fa4468b-eab3-4f2f-b189-96d416083f70)

### After Process
**Virus & Threat Protection tab and antimalware service executable** is removed.
**Scan with microsoft defender** context menu is also removed.
![1735930499798](https://github.com/user-attachments/assets/23b2fa4d-69d6-43a1-a043-11a3e70f6e71)

### How it works?
In windows PE we have more permission than user-mode, script removes services, registry keys, and application data of defender.

### Steps
* Download **beatDefender.bat** from releases, move to desktop.
* Enter recovery mode (hold shift and click to "restart" button is the easiest way)
* Go to **Troubleshoot > Advanced > Command line**

Write following code
```cmd
C:
cd Users/YOUR_USERNAME_HERE/Desktop
beatDefender.bat
```
After process is complete, restart your PC.


