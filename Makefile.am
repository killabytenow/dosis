###############################################################################
# Makefile.am
#
# File that will be processed by Automake that describes how to make the main
# Makefile that will drive the building of this software.
#
# -----------------------------------------------------------------------------
# dosis - DoS: Internet Sodomizer
#   (C) 2008 Gerardo García Peña <gerardo@kung-foo.dhs.org>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the Free
#   Software Foundation; either version 2 of the License, or (at your option)
#   any later version.
#
#   This program is distributed in the hope that it will be useful, but WITHOUT
#   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
#   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
#   more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc., 51
#   Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
###############################################################################

# This directories haw more Makefile's to process
SUBDIRS = include src

# Here we say which files must be added to the distribution (config files,
# licenses, ...)
EXTRA_DIST = BUGS
doc_DATA = AUTHORS COPYING ChangeLog NEWS README BUGS
dist_man1_MANS = doc/man/dosis.1

# Set the warning level to maximum and add directory 'include' to the include
# search path.
CFLAGS = -I$(srcdir)/include

