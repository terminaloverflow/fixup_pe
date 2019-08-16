About
=====
A Ruby script to modify a PE binary, performing several actions:

* Add the IMAGE_FILE_LARGE_ADDRESS_AWARE flag to the binary. This flag allows a 32 bit PE binary to address more than 2Gb of address space at run time.

* Add the IMAGE_DLLCHARACTERISTICS_NX_COMPAT flag to the binary. This flag indicates the binary is Data Execution Prevention (DEP) compatible.

* Add the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag to the binary. This flag indicates the binary can opt into Address Space Layout Randomization (ASLR).

* Remove any symbol information pre-pended to be binary.

* Calculate the expected SizeOfHeaders value in the PE optional header and update the value if the existing value is wrong. Some linkers produce an incorrect SizeOfHeaders value.

This script can be run as part of a build to fixup PE binaries that would benefit from any of the above modifications.

Usage
=====
ruby.exe fixup_pe.rb [/flag_laa] [/flag_dep] [/flag_aslr] [/strip_symbols] [/fix_sizeof] c:\\path\\to\\file.exe

License
=======
Released under the 3-Clause BSD License.