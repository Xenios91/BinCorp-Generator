'''
Tool for generating binary executables corpus for dynamic analysis
'''

import argparse
import logging
from typing import List

import yaml

from corpus_generator import ArgumentDetails, CorpusGenerator


def get_args():
    '''
    Gets cli args for this tools
    '''

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='Generate a test corpus for binary analysis tools')
    parser.add_argument(
        '--config', type=str, required=True, help='The config yaml file to use for argument configuration')

    args: argparse.Namespace = parser.parse_args()
    return args


def read_config(config_file_name: str) -> dict:
    '''
    Opens the binary objects config file to read in details on how to parse it.
    '''
    with open(config_file_name, 'r', encoding='utf-8') as config_file:
        yaml_contents = yaml.safe_load(config_file)
        return yaml_contents


def _print_logo():
    logo = """  ____  _        _____                        _____                           _             
 |  _ \(_)      / ____|                      / ____|                         | |            
 | |_) |_ _ __ | |     ___  _ __ _ __ ______| |  __  ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
 |  _ <| | '_ \| |    / _ \| '__| '_ \______| | |_ |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
 | |_) | | | | | |___| (_) | |  | |_) |     | |__| |  __/ | | |  __/ | | (_| | || (_) | |   
 |____/|_|_| |_|\_____\___/|_|  | .__/       \_____|\___|_| |_|\___|_|  \__,_|\__\___/|_|   
                                | |                                                         
                                |_|                                                         
"""
    print(logo)


def start():
    '''
    Initiates the program
    '''
    _print_logo()
    logging.getLogger('angr').setLevel('ERROR')
    logging.getLogger('cle').setLevel('ERROR')
    args: argparse.Namespace = get_args()

    print("Loading config...", end=" ")

    config_file_name: str = args.config
    config: dict = read_config(config_file_name)

    args_list: List[ArgumentDetails] = []
    for _ in range(config.get("arg_count")):
        arg_size: int = int(config.get("args_size"))
        args_list.append(ArgumentDetails(arg_size))

    filename: str = config.get("binaryfile")
    max_offsets = config.get("max_offsets")

    print("Config Loaded!")

    bin_solver: CorpusGenerator = CorpusGenerator(filename, args_list, max_offsets)
    bin_solver.generate_corpus()


if __name__ == "__main__":
    start()
