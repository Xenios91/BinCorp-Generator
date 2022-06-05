# BinCorp-Generator

## General Information
- Author: Corey Hartman
- Language: Python 3.10
- Description: Analyzes binary executables and generates a test corpus to reach every basic block detected in non library/Shared object sections of the text.

## Setup
- Requires Python 3.10
- DevContainer included within the project.
- Install requirements ```pip install -r requirements.txt```
- Note: I recommend using a Python virtual environment

## Utilization
- Set the binary file and argument configuration within a yaml file, use the -config flag to set the configuration. ```-config=config.yml``` An example version of this file is available, named ```example.yml```
- The output files containing both stdin and CLI args for reaching multiple paths will be output in two text files ending with .dump


