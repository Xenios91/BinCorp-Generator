import argparse
from typing import List

import yaml

from argument_details import ArgumentDetails
from corpus_generator import CorpusGenerator


def get_args():
    '''
    Gets cli args for this tools
    '''

    parser = argparse.ArgumentParser(
        description='Generate a test corpus for binary analysis tools')
    parser.add_argument(
        '--config', type=str, required=True, help='The config yaml file to use for argument configuration')

    args = parser.parse_args()
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
    args = get_args()
    config_file_name = args.config
    config = read_config(config_file_name)

    args_list: List[ArgumentDetails] = list()
    for _ in range(config.get("arg_count")):
        arg_size = int(config.get("args_size"))
        args_list.append(ArgumentDetails(arg_size))

    bin_solver = CorpusGenerator("a.out", args_list)
    bin_solver.generate_corpus()


if __name__ == "__main__":
    start()
