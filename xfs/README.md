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
```

# Example

```
$ python3 meta.py -i <path_to_xfs_formatted_disk_image> -o <path_to_output_csv>
```