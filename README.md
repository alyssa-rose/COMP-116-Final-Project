This is the README for the final project in COMP 116: Introduction to Cybersecurity at Tufts University for the Fall 2019 semester. The paper, 'Starting from Stuxnet: The Development of the US-Iranian Cyberwar' seeks to understand the cyber conflict between the United States and Iran, which began after the release of Stuxnet in 2010. The paper considers the main Iranian actors in the conflict, a group known as 'APT33' (aka Elfin, Refined Kitten, Magnallium, Holmium) and the tactics they use including spear phishing, a dropper known as DROPSHOT, a wiper malware called SHAPESHIFT (aka StoneDrill) which is similar to the goals of Shamoon (another wiper malware that has not been formally attributed to APT33), and a backdoor called TURNEDUP.

This repository contains the analysis of the Stuxnet source code, and proof of concepts for DROPSHOT, SHAPESHIFT, and TURNEDUP.



Stuxnet
=======

Contains (nearly complete) source code for Stuxnet as pulled from Michael R. Torres' (Github username: micrictor) GitHub under the 'stuxnet' repository. References as written on the README from that repository include:

        1.) Initial base provided by https://github.com/Christian-Roggia/open-myrtus
        2.) http://www.codeproject.com/Articles/246545/Stuxnet-Malware-Analysis-Paper
        3.) https://www.esetnod32.ru/company/viruslab/analytics/doc/Stuxnet_Under_the_Microscope.pdf
        
All source code for Stuxnet included in the Dropper and Rootkit folders, and the analysis of the source code is in the 'Analysis' file in the Stuxnet folder, which contains code snippets




DROPSHOT
========
DROPSHOT is the dropper used by APT33 to install both SHAPESHIFT (wiper malware) and TURNEDUP (backdoor). APT33 is the only group known to use DROPSHOT. The code included is a proof of concept of how DROPSHOT was written, using references:




SHAPESHIFT (/Shamoon. Also known as 'StoneDrill')
=====================
SHAPESHIFT is the wiper malware used by APT33 (dropped by DROPSHOT) and similar to Shamoon (although Shamoon has not been formally attributed to APT33). Code in this folder is a proof of concept, written using references:




TURNEDUP
=========
TURNEDUP is the backdoor used by APT33 (dropped by DROPSHOT), and coded written is a proof of concept, written using references:
