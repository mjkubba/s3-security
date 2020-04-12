# s3-security
Tool to scan and fix Versioning (enable), encryption (check for any and enable AES256) and SSL policy (enforce secure connections)   

## How to use:
### requirement:
#### AWS:
You'll need to have your aws creds set (using aws configure or other methods)   
#### Python:
You need to pip install
* boto3
* logging
* coloredlogs   
or `pip install -r requirement.txt`
### To run:
`python s3.py` This will scan all buckets and create s3results.csv with the findings
### additional flags:
`-b` to scan a specific bucket by name eg: `python s3.py -b myawesomeBucket`
`-f` to fix versioning, encryption and ssl issues found, eg: `python s3.py -f`

you can also combine both flags, eg: `python s3.py -f -b myawesomeBucket`
