###############################################################################
# Makefile.am
#
# File for Autoconf/Automake that describes how to create the Makefile which
# will build Dosis.
#
# -----------------------------------------------------------------------------
# dosis - DoS: Internet Sodomizer
#   (C) 2008 Gerardo García Peña <gerardo@kung-foo.net>
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

bin_PROGRAMS = dosis
dosis_SOURCES = dosis.c           dosis.h           \
                dosconfig.c       dosconfig.h       \
                ip.c              ip.h              \
                ipqex.c           ipqex.h           \
                hash.c            hash.h            \
                help.c            help.h            \
                lnet.c            lnet.h            \
                log.c             log.h             \
                mqueue.c          mqueue.h          \
                payload.c         payload.h         \
                pthreadex.c       pthreadex.h       \
                script.y          script.h          \
                tea.c             tea.h             \
                                  teatype.h         \
                pills/listener.c  pills/listener.h  \
                pills/sender.c    pills/sender.h    \
                pills/slowy.c     pills/slowy.h     \
                pills/tcp.c       pills/tcp.h       \
                pills/tcpopen.c   pills/tcpopen.h   \
                pills/tcpraw.c    pills/tcpraw.h    \
                pills/udp.c       pills/udp.h
if SSL_ENABLED
dosis_SOURCES += sslthread.c      sslthread.h
endif

AM_CFLAGS = -DYYERROR_VERBOSE

splint: $(dosis_SOURCES:%.y=%.c)
	splint -f dosis.splintrc $(DEFS) $(DEFAULT_INCLUDES) $(dosis_SOURCES:%.y=%.c)

