# Yara---Static-Analysis-Using-Strings-Observables-and-Binary-Code-Analysis.

•	Used Yara as a pattern-matching engine to identify and categorize malware samples.

•	Selected a malware sample from the given ZIP bundle, and used strings analysis to extract some significant strings from the malware and build a Yara rule that meets the following criteria:

    1.	The malware sample is an EXE file.
    2.	Matches the artifact I chose.
    3.	Matches other artifacts that are from the same family. This means that I have gone through the malware samples provided, and               reviewed the multiple malware samples, and then found a few that appear similar. Typically, files containing similar strings, as           well as those for which ‘objdump’ tool displays similar DLL imports and imported symbols, are both good ways to identify                   similarities.
    4.	Doesn’t match on any legitimate windows programs.

# Submission consists of a 
1.	Yara signature. 
2.	The text file containing the description of which malware sample(s) I used to derive my signature (either the filenames, MD5, SHA-1, or SHA-256 checksums) as well as which malware samples I found to be matched by my signature. So, for instance, after I’ve written my signature, and run it against the full directory of samples,I might find that it matches other malware provided(in ZIP Bundle ) but I did not necessarily use to build the signature.
