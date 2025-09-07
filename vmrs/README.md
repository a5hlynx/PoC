# Description

Converts memorydumps in the format of VMRS to raw memorydumps. It requires vmsavedstatedumpprovider.dll matching the architecture of the environment where it runs should be placed in the same folder or one of the folders defined by $env:PATH. vmsavedstatedumpprovider.dll is included in Windows SDK.

# Usage

```
> .\vmrs2raw.ps1 -InputPath <Path to input VMRS file> -OutputPath <Path to output RAW file>

> .\vmrs2raw.ps1

cmdlet vmrs2raw.ps1 at command pipeline position 1
Supply values for the following parameters:
InputPath:<Path to input VMRS file>
OutputPath:<Path to output RAW file>
```

# Examples

```
> .\vmrs2raw.ps1  -InputPath .\98850815-81E1-4123-B800-1EF08C2FF8BE.VMRS `
>> -OutputPath .\98850815-81E1-4123-B800-1EF08C2FF8BE.raw
Conversion initiated
Processing chunk 1 of 2
  Start: 0x0
  Pages: 262144
  Size:  0x40000000 bytes
    Progress:   1000/262144 pages
    Progress:   2000/262144 pages
    Progress:   3000/262144 pages
        
..snip..


> .\vmrs2raw.ps1

cmdlet vmrs2raw.ps1 at command pipeline position 1
Supply values for the following parameters:
InputPath: 98850815-81E1-4123-B800-1EF08C2FF8BE.VMRS
OutputPath: 98850815-81E1-4123-B800-1EF08C2FF8BE.raw
Conversion initiated
Processing chunk 1 of 2
  Start: 0x0
  Pages: 262144
  Size:  0x40000000 bytes
    Progress:   1000/262144 pages
    Progress:   2000/262144 pages
    Progress:   3000/262144 pages
        
..snip..


```