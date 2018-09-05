#!/usr/bin/env python2
# Copyright (C) 2018 Guillaume Valadon <guillaume@valadon.net>

"""
Automatically generate r2m2.h
"""

import argparse
import sys
import os
import subprocess


from jinja2 import Environment, FileSystemLoader


def preprocessor(include_directory, include_filename):
    """Call gcc preprocessor on the include file."""

    command = ["gcc", "-E", "-I%s" % include_directory, include_filename]

    try:
        processed = subprocess.check_output(command)
    except OSError:
        sys.exit("preprocessor(): gcc can't be executed !")
    except subprocess.CalledProcessError as cpe:
        sys.exit("preprocessor(): got %s" % cpe)

    return processed


def get_between(content, pattern_start, pattern_stop):
    """Get lines betweem two patterns."""

    # Split the include file content
    lines = content.split("\n")
    lines = [l for l in lines if len(l) and l[0] != '#']

    # Get lines numbers
    lnum_start = [i for i in xrange(len(lines)) if pattern_start in lines[i]]
    lnum_stop = [i for i in xrange(len(lines)) if pattern_stop in lines[i]]

    # Get the indexes
    lnum_stop = lnum_stop[0]
    lnum_start = [lnum for lnum in lnum_start if lnum < lnum_stop][-1]

    return "\n".join(lines[lnum_start:lnum_stop+1])


def extract_structure(include_content, structure_name):
    """Extract a radare2 structure and transform it."""

    structure = get_between(include_content, "typedef", "} %s;" % structure_name)

    # Rename the structure names
    structure = structure.replace("_t {", "_t_r2m2 {")
    structure = structure.replace("%s;" % structure_name, "%s_r2m2;" % structure_name)

    return structure


def get_RList(directory):
    """Get the RList structure"""

    # Get the preprocessed include file content
    filename = "%s/r_list.h" % directory
    include_content = preprocessor(directory, filename)

    # Extract the RList structure and its dependencies
    RList_structure = [l for l in include_content.split("\n") if "typedef" in l and "RListFree" in l][0]
    RList_structure += extract_structure(include_content, "RListIter")
    RList_structure += extract_structure(include_content, "RList").replace("RListIter", "RListIter_r2m2")
    RList_structure = RList_structure.replace("RListFree", "RListFree_r2m2")
    return RList_structure


def get_RAsmOp_structure(directory):
    """Get and transform the RAsmOp structure and dependencies"""

    # Get the preprocessed include file content
    filename = "%s/r_util/r_mem.h" % directory
    include_content = preprocessor(directory, filename)

    # Extract the RBuffer structure
    RMmap_structure = extract_structure(include_content, "RMmap").replace("ut8", "unsigned char")
    RMmap_structure = RMmap_structure.replace("ut64", "unsigned long long")

    # Get the preprocessed include file content
    filename = "%s/r_util/r_buf.h" % directory
    include_content = preprocessor(directory, filename)

    # Extract the RList structure
    RList_structure = get_RList(directory)

    # Extract the RBuffer structure
    RBuffer_structure = extract_structure(include_content, "RBuffer").replace("ut8", "unsigned char")
    RBuffer_structure = RBuffer_structure.replace("ut64", "unsigned long long")
    RBuffer_structure = RBuffer_structure.replace("st64", "long long")
    RBuffer_structure = RBuffer_structure.replace("bool", "char")
    RBuffer_structure = RBuffer_structure.replace("RMmap", "RMmap_r2m2")
    RBuffer_structure = RBuffer_structure.replace("RList", "RList_r2m2")

    # Get the preprocessed include file content
    filename = "%s/r_asm.h" % directory
    include_content = preprocessor(directory, filename)
    # Extract the RAsmOp structure
    RAsmOp_structure = extract_structure(include_content, "RAsmOp").replace("RBuffer", "RBuffer_r2m2")

    # Patch some values
    RAsmOp_structure = RAsmOp_structure.replace("255 + 1", "256")

    # Get the preprocessed include file content
    filename = "%s/r_util.h" % directory
    include_content = preprocessor(directory, filename)

    # Extract the RStrBuf structure
    RStrBuf_structure = extract_structure(include_content, "RStrBuf")
    RAsmOp_structure = RAsmOp_structure.replace("RStrBuf", "RStrBuf_r2m2")

    return RList_structure + RMmap_structure + RBuffer_structure + RStrBuf_structure + RAsmOp_structure


def get_RAnalOp_structure(directory):
    """Get and transform the RAnalOp structure"""

    structures = list()

    # Get the preprocessed include file content
    filename = "%s/r_list.h" % directory
    include_content = preprocessor(directory, filename)

    # Get the preprocessed include file content
    filename = "%s/r_reg.h" % directory
    include_content = preprocessor(directory, filename)

    # Extract the RRegItem structure
    RRegItem_structure = extract_structure(include_content, "RRegItem")
    structures.append(RRegItem_structure)

    # Get the preprocessed include file content
    filename = "%s/r_anal.h" % directory
    include_content = preprocessor(directory, filename)

    # Extract the RAnalVar structure
    RAnalVar_structure = extract_structure(include_content, "RAnalVar")
    RAnalVar_structure = RAnalVar_structure.replace("RList", "RList_r2m2")
    structures.append(RAnalVar_structure)

    # Extract the RAnalValue structure
    RAnalValue_structure = extract_structure(include_content, "RAnalValue")
    RAnalValue_structure = RAnalValue_structure.replace("RRegItem", "RRegItem_r2m2")
    structures.append(RAnalValue_structure)

    # Extract the RAnalSwitchOp structure
    RAnalSwitchOp_structure = extract_structure(include_content, "RAnalSwitchOp")
    RAnalSwitchOp_structure = RAnalSwitchOp_structure.replace("RList", "RList_r2m2")
    structures.append(RAnalSwitchOp_structure)

    # Extract the RAnalHint structure
    RAnalHint_structure = extract_structure(include_content, "RAnalHint")
    structures.append(RAnalHint_structure)

    # Extract the structure
    RAnalOp_structure = extract_structure(include_content, "RAnalOp")
    RAnalOp_structure = RAnalOp_structure.replace("RAnalVar", "RAnalVar_r2m2")
    RAnalOp_structure = RAnalOp_structure.replace("RAnalHint", "RAnalHint_r2m2")
    RAnalOp_structure = RAnalOp_structure.replace("RAnalValue", "RAnalValue_r2m2")
    RAnalOp_structure = RAnalOp_structure.replace("RStrBuf", "RStrBuf_r2m2")
    RAnalOp_structure = RAnalOp_structure.replace("RAnalSwitchOp", "RAnalSwitchOp_r2m2")
    structures.append(RAnalOp_structure)

    return "\n".join(structures)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="radare2 directory containing include files")
    args = parser.parse_args()

    # Check if the directory exists
    if not os.path.exists(args.directory):
        print >> sys.stderr, "Directory %s does not exist !" % args.directory
        sys.exit()

    # Get radare2 structures
    RAsmOp_str = get_RAsmOp_structure(args.directory)
    RAnalOp_str = get_RAnalOp_structure(args.directory)

    # Access jinja2 templates
    j2env = Environment(loader=FileSystemLoader("src/"))

    # Load and render the .h file
    r2m2h = j2env.get_template("r2m2.h.j2")
    fd = open("src/r2m2.h", "w")
    print >> fd, r2m2h.render(RAsmOp=RAsmOp_str, RAnalOp=RAnalOp_str)
    fd.close()
