# BinCorp-Generator

## General Information
- Author: Corey Hartman
- Language: Python 3.10
- Description: Analyzes binary executables and generates a test corpus to reach every basic block detected in non library/Shared object parts of the bin's text section.

## Setup
- Requires Python 3.10
- DevContainer included within the project.
- Install requirements ```pip install -r requirements.txt```
- Note: I recommend using a Python virtual environment

## Utilization
- Set the binary file and argument configuration within a yaml file, use the --config flag to set the configuration. ```--config=example.yml``` An example version of this file is available, named ```example.yml```
- The output files containing both stdin and CLI args for reaching multiple paths will be output in two text files ending with .dump
- Values and their explaination for configuration can be found in the example file: ```example.yml```

## Config File
The config file has a few values to set the following are the descriptions:
```
binaryfile: "myBin" #file name
arg_count: 2 #number of CLI arguments
args_size: 256 #byte size
max_offsets: -1 #max number of offsets to search, set this to avoid resource exhaustion, -1 == unlimited
offsets: [] #if array set, these offsets will only be searched
```

