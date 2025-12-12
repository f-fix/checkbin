# checkbin
Python implementation of Softkey's CHECKBIN checksum routine. This checksum routine and hex dumper were used for Apple II programs in various Softkey publications; for more information, refer to http://justsolve.archiveteam.org/wiki/Checkbin/Checksoft

## usage
```bash
python3 checkbin.py INFILENAME BEGADDRHEX [ENDADDRHEX]
```
this reads a raw (unheadered) binary file INFILENAME, and prints out a hex dump including CHECKBIN-style checksums, with BEGADDRHEX being the address to display for the first byte of the file, and the optional ENDADDRHEX being the corresponding address for the last byte of the file

An example:
```bash
echo -n "HELLO WORLD" > test.bin
python3 checkbin.py test.bin 4444
```
outputs:
```
'test.bin' BEG: *4444.444E END:

4444- 48 45 4C 4C              $2796
4448- 4F 20 57 4F 52 4C 44     $E50F
```
equivalent output from the Softkey CHECKBIN running in an Apple II emulator: (Ctrl-Y was pressed before Return on the last line)
<br />
<img width="615" height="424" alt="image" src="https://github.com/user-attachments/assets/428b947c-cbed-4faa-a1bb-d6662b61c353" />
