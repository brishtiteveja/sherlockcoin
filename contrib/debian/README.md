
Debian
====================
This directory contains files used to package sherlockcoind/sherlockcoin-qt
for Debian-based Linux systems. If you compile sherlockcoind/sherlockcoin-qt yourself, there are some useful files here.

## sherlockcoin: URI support ##


sherlockcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install sherlockcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your sherlockcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/sherlockcoin128.png` to `/usr/share/pixmaps`

sherlockcoin-qt.protocol (KDE)

