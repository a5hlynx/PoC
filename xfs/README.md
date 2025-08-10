# Description

Parsers for XFS-formatted disk images. meta.py extracts, parses and write inodes into csv, while journal.py does the same for journal logs.

# Usage

```
$ python3 meta.py -h
usage: meta.py [-h] -i INPUT -o OUTPUT [-d]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        specify disk image
  -o OUTPUT, --output OUTPUT
                        specify output file
  -d, --deleted         specify to search deleted objects

$ python3 journal.py -h
usage: journal.py [-h] -i INPUT -o OUTPUT [-t]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        specify disk image
  -o OUTPUT, --output OUTPUT
                        specify output file
  -t, --trans           show transaction ids
```

# Examples

```
$ python3 meta.py -i <path_to_xfs_formatted_disk_image> -o <path_to_output_csv>
$ python3 journal.py -i <path_to_xfs_formatted_disk_image> -o <path_to_output_csv>
```