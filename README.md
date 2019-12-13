This is the README for the final project in COMP 116: Introduction to Cybersecurity at Tufts University for the Fall 2019 semester. The paper, 'Starting from Stuxnet: The Development of the US-Iranian Cyberwar' seeks to understand the cyber conflict between the United States and Iran, which began after the release of Stuxnet in 2010. The paper considers the main Iranian actors in the conflict, a group known as 'APT33' (aka Elfin, Refined Kitten, Magnallium, Holmium) and the tactics they use including spear phishing, a dropper known as DROPSHOT, a wiper malware called SHAPESHIFT (aka StoneDrill) which is similar to the goals of Shamoon (another wiper malware that has not been formally attributed to APT33), and a backdoor called TURNEDUP.

This repository contains an analysis of Shamoon (as stand in/proof of concept for what SHAPESHIFT looks like), analysis of ALFASHELL (webshell that APT33 used for its spear phishing module) which includes the spear phishing source code from the malicious .hta file that was linked in emails sent to targets, and the source code of Stuxnet.


SHAPESHIFT (/Shamoon. Also known as 'StoneDrill')
=====================
SHAPESHIFT is the wiper malware used by APT33 (dropped by DROPSHOT) and similar to Shamoon (although Shamoon has not been formally attributed to APT33). This file contains a full analysis of the Shamoon code as found on 
https://github.com/christian-roggia/open-shamoon/tree/master/open-malware/Modules

As the SHAPESHIFT code could not be found online as it's still not publicly available, analysis of the Shamoon code 
serves as a proof of concept analysis of what SHAPESHIFT may actually look like as it achieves the same goal of 
Shamoon, albeit more sophisticated (as seen in the ability for DROPSHOT to use more advanced anti-emulation techniques and uses external scripts for self destruction)


ALFASHELL
========
Includes analysis of the malicious code embedded in .hta files (HTML application files) that were included in emails
sent to employees at aerospace and energy companies. The code comes from the spear phishing module of ALFA TEaM SHELL (ALFA-SHELL-V3), a web based shell.


Stuxnet
=======

Contains (nearly complete) source code for Stuxnet as pulled from Michael R. Torres' (Github username: micrictor) GitHub under the 'stuxnet' repository. References as written on the README from that repository include:

        1.) Initial base provided by https://github.com/Christian-Roggia/open-myrtus
        2.) http://www.codeproject.com/Articles/246545/Stuxnet-Malware-Analysis-Paper
        3.) https://www.esetnod32.ru/company/viruslab/analytics/doc/Stuxnet_Under_the_Microscope.pdf
        
All source code for Stuxnet included in the Dropper and Rootkit folders, and the analysis of the source code is in the 'Analysis' file in the Stuxnet folder, which contains code snippets
