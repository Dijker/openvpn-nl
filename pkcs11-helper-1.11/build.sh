#!/bin/bash

autoreconf -i
./configure
make
sudo make install
