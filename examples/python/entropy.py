#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Inspired from binwalk: https://github.com/devttys0/binwalk/
#
# Description:
# Show show entropy of the differents binary's section
#
# Requirement: pyqtgraph


import pyqtgraph as pg
import sys
import math
from lief import parse, ELF, PE
from pyqtgraph.Qt import QtCore, QtGui


class Entropy(object):

    DEFAULT_BLOCK_SIZE  = 512
    DEFAULT_DATA_POINTS = 2048
    DEFAULT_THRESHOLD   = 9

    def __init__(self, path):
        self.binary     = parse(path)
        self.block_size = None
        self.result     = dict((section, []) for section in self.binary.sections)


    def entropy(self, data):
        entropy = 0

        if data:
            length = len(data)

            seen = dict(((x, 0) for x in range(0, 256)))
            for byte in data:
                seen[byte] += 1

            for x in range(0, 256):
                p_x = float(seen[x]) / length
                if p_x > 0:
                    entropy -= p_x * math.log(p_x, 2)

        return (entropy)

    def compute_entropy_section(self, section):
        content = section.content
        size    = len(content)

        if self.block_size is None:
            block_size = size / self.DEFAULT_DATA_POINTS
            # Round up to the nearest DEFAULT_BLOCK_SIZE
            block_size = int(block_size + ((self.DEFAULT_BLOCK_SIZE - block_size) % self.DEFAULT_BLOCK_SIZE))
        else:
            block_size = self.block_size

        if block_size <= 0:
            block_size = self.DEFAULT_BLOCK_SIZE

        i = 0
        while (i + block_size) < size:
            entropy = self.entropy(content[i:i + block_size])
            self.result[section].append((section.offset + i , entropy))
            i += block_size


    def plot(self):
        plt = pg.plot(title = "Entropy")
        plt.addLegend()

        for idx, (section, result) in enumerate(self.result.items()):
            x = []
            y = []
            for offset, entropy in result:
                x.append(offset)
                y.append(entropy)
            if len(result) > self.DEFAULT_THRESHOLD:
                c1 = plt.plot(x, y,\
                        pen=pg.intColor(idx * 10, 100),\
                        name=section.name,\
                        antialias = True,\
                        fillLevel=0,\
                        fillBrush=pg.intColor(idx * 10, 100, alpha = 40))

    def run(self):

        for section in self.binary.sections:
            self.compute_entropy_section(section)
        self.plot()

        if (sys.flags.interactive != 1) or not hasattr(QtCore, 'PYQT_VERSION'):
            QtGui.QApplication.instance().exec_()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <binary>".format(sys.argv[0]))
        sys.exit(0);

    Entropy(sys.argv[1]).run()

