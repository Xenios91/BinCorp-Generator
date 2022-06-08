# BinCorp-Generator

## General Information
- Author: Corey Hartman
- Language: Python 3.10
- Supported Architectures: MIPS, ARM, x86, x86-64
- Description: Analyzes binary executables and can generate a test corpus for defined instruction paths, each discovered function, or it can generate a test corpus to reach every basic block detected in non library/Shared object parts of the bin's text section.

## Setup
- Requires Python 3.10
- DevContainer included within the project.
- Install requirements ```pip install -r requirements.txt```
- Note: I recommend using a Python virtual environment

## Utilization
- Set the binary file and argument configuration within a yaml file, use the --config flag to set the configuration. ```--config=example.yml``` An example version of this file is available, named ```example.yml```
- The output files containing both stdin and CLI args for reaching multiple paths will be output in two text files ending with .dump
- Values and their explaination for configuration can be found in the example file: ```example.yml```
- The ```--verbose``` flag can be set to allow all INFO and greater logging to go to STDOUT.

## Config File
The config file has a few values to set the following are the descriptions:
```
binaryfile: "myBin" #file name
arg_count: 2 #number of CLI arguments
args_size: 256 #byte size
max_offsets: -1 #max number of offsets to search, set this to avoid resource exhaustion, -1 == unlimited
offsets: #an array of offets, 'function' or 'basic_block' is available, if the word function is used, the tool will return inputs to reach each function,  if basic block is set, the tool will return input to reach all basic blocks, and an array of offsets will only look for those defined instruction locations
```

