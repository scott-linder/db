#!/bin/bash
curl -L 'https://downloads.sourceforge.net/udis86/udis86-1.7.2.tar.gz' | tar xfz -
cd udis86-1.7.2
./configure --prefix=/usr
make
sudo make install
