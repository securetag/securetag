
Debian
====================
This directory contains files used to package securetagd/securetag-qt
for Debian-based Linux systems. If you compile securetagd/securetag-qt yourself, there are some useful files here.

## securetag: URI support ##


securetag-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install securetag-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your securetag-qt binary to `/usr/bin`
and the `../../share/pixmaps/securetag128.png` to `/usr/share/pixmaps`

securetag-qt.protocol (KDE)

