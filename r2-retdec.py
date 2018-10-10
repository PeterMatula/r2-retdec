#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys

import r2pipe


def parse_args(_args):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('file',
                        metavar='FILE',
                        help='The input file.')

    parser.add_argument('-r', '--retdec',
                        dest='retdec',
                        metavar='FILE',
                        required=True,
                        help='Path to the main retdec decompilation script (retdec-decompiler.py).')

    parser.add_argument('-f', '--function',
                        dest='function',
                        metavar='ADDRESS',
                        required=True,
                        help='Address inside a function to decompile.')

    return parser.parse_args(_args)


def to_address(a):
    return hex(a)


def drop_prefix(str, prefix):
    if str.startswith(prefix):
        return str[len(prefix):]
    return str


def to_calling_convention(cc):
    """Translate r2 ccs to retdec ccs if they are not the same."""
    return cc


def generate_basic(r2, config):
    file_info = r2.cmdj('ij')

    config['ida'] = True
    config['inputFile'] = file_info['core']['file']
    try:
        config['entryPoint'] = to_address(r2.cmdj('iej')[0]['vaddr'])
    except IndexError:
        pass


def generate_functions(r2, config):
    funcs = list()

    rfncs = r2.cmdj('aflj')
    for rf in rfncs:
        f = generate_function(r2, rf)
        if f:
            funcs.append(f)

    config['functions'] = funcs


def generate_function(r2, rf):
    f = dict()

    f['name'] = drop_prefix(rf['name'], 'sym.')
    f['startAddr'] = to_address(int(rf['minbound']))
    f['endAddr'] = to_address(int(rf['maxbound']))
    f['callingConvention'] = to_calling_convention(rf['calltype'])
    f['fncType'] = 'userDefined'

    return f


def generate_config(r2):
    config = dict()

    generate_basic(r2, config)
    generate_functions(r2, config)

    return config


def generate_retdec_arguments(args, config_name, selected_fnc, output):
    rargs = list()

    rargs.append('python')
    rargs.append(args.retdec)
    rargs.append(args.file)
    rargs.append('--config')
    rargs.append(config_name)
    rargs.append('--select-decode-only')

    rargs.append('--select-ranges')
    start = selected_fnc[0]['offset']
    end = start + selected_fnc[0]['size']
    rargs.append(hex(start) + '-' + hex(end))

    rargs.append('-o')
    rargs.append(output)

    return rargs


if __name__ == '__main__':

    args = parse_args(sys.argv[1:])

    # Analyze input file in r2.
    #
    r2 = r2pipe.open(args.file)
    r2.cmd('aaa')

    # Find the selected function.
    #
    selected_fnc = r2.cmdj('afij ' + args.function)
    if not selected_fnc:
        print('No function at selected address: %s' % args.function, file=sys.stderr)
        sys.exit(1)

    # Generate JSON config.
    #
    config = generate_config(r2)
    config_name = os.path.abspath(args.file) + '.json'
    with open(config_name, 'w') as config_file:
        json.dump(config, config_file, sort_keys=True, indent=4)

    # Execute RetDec command.
    #
    output = args.file + '.retdec.c'
    rargs = generate_retdec_arguments(args, config_name, selected_fnc, output)
    if subprocess.call(rargs, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
        print('Decompilation failed. Arguments: %s' % str(rargs), file=sys.stderr)
        sys.exit(1)

    # Dump output C.
    #
    with open(output, 'r') as output_file:
        print(output_file.read())
