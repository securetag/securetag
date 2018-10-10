#!/bin/sh

for size in 256 128 64 32 16; do
    convert securetag.png -resize "${size}x${size}" "securetag${size}.png"
    convert securetag.png -resize "${size}x${size}" "securetag${size}.xpm"
done
