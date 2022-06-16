rule unknown_threat {
  meta:
    Author ="@vinayak"
    Description = "Custom rule for detecting undetected threat"

  strings:
    $a = "ppxxmr.com"
  condition:
    $a

}


//Result of the scan shown below
ubuntu@ubuntu-VirtualBox:~/Downloads$ clamscan -ir -d ~/rulers .
./tmplog: YARA.unknown_threat.UNOFFICIAL FOUND

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 0.100.3
Scanned directories: 1
Scanned files: 8
Infected files: 1
Data scanned: 2.40 MB
Data read: 2.40 MB (ratio 1.00:1)
Time: 0.138 sec (0 m 0 s)
