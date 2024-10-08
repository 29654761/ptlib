#
# ptlib_config.mak
#
# mak rules to be included in a ptlib application Makefile.
#
# Portable Tools Library
#
# Copyright (c) 1993-2013 Equivalence Pty. Ltd.
#
# The contents of this file are subject to the Mozilla Public License
# Version 1.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
# the License for the specific language governing rights and limitations
# under the License.
#
# The Original Code is Portable Windows Library.
#
# The Initial Developer of the Original Code is Equivalence Pty. Ltd.
#
# Portions are Copyright (C) 1993 Free Software Foundation, Inc.
# All Rights Reserved.
# 
# Contributor(s): ______________________________________.
#

PTLIB_MAJOR :=@PTLIB_MAJOR@
PTLIB_MINOR :=@PTLIB_MINOR@
PTLIB_STAGE :=@PTLIB_STAGE@
PTLIB_PATCH :=@PTLIB_PATCH@
PTLIB_OEM   :=@PTLIB_OEM@

# detected platform
target      := @target@
target_os   := @target_os@
target_cpu  := @target_cpu@

# The install directories
ifndef prefix
  prefix := @prefix@
endif
ifndef exec_prefix
  exec_prefix := @exec_prefix@
endif
ifndef libdir
  libdir := @libdir@
endif
ifndef includedir
  includedir := @includedir@
endif
ifndef datarootdir
  datarootdir := @datarootdir@
endif

# Tool names detected by configure
CC      := @CC@
CXX     := @CXX@
LD      := @LD@
AR      := @AR@
RANLIB  := @RANLIB@
STRIP   := @STRIP@
OBJCOPY := @OBJCOPY@
DSYMUTIL:= @DSYMUTIL@
LN_S    := @LN_S@
MKDIR_P := @MKDIR_P@
BISON   := @BISON@
INSTALL := @INSTALL@
SVN     := @SVN@
GIT     := @GIT@

CPPFLAGS          := @CPPFLAGS@ $(CPPFLAGS)
CXXFLAGS          := @CXXFLAGS@ $(CXXFLAGS)
CFLAGS            := @CFLAGS@ $(CFLAGS)
LDFLAGS           := @LDFLAGS@ $(LDFLAGS)
LIBS              := @LIBS@ $(LIBS)
SHARED_CPPFLAGS   := @SHARED_CPPFLAGS@
SHARED_LDFLAGS     = @SHARED_LDFLAGS@
DEBUG_CPPFLAGS    := @DEBUG_CPPFLAGS@
DEBUG_CFLAGS      := @DEBUG_CFLAGS@
OPT_CPPFLAGS      := @OPT_CPPFLAGS@
OPT_CFLAGS        := @OPT_CFLAGS@
CPLUSPLUS_STD     := @CPLUSPLUS_STD@
ARFLAGS           := @ARFLAGS@
YFLAGS            := @YFLAGS@

SHAREDLIBEXT      := @SHAREDLIBEXT@
STATICLIBEXT      := @STATICLIBEXT@
DEBUGINFOEXT      := @DEBUGINFOEXT@

PTLIB_PLUGIN_SUFFIX := _ptplugin

PTLIB_PLUGIN_DIR  := @PTLIB_PLUGIN_DIR@

P_PROFILING       := @P_PROFILING@
HAS_ADDRESS_SANITIZER := @HAS_ADDRESS_SANITIZER@
HAS_THREAD_SANITIZER := @HAS_THREAD_SANITIZER@

HAS_NETWORKING    := @HAS_NETWORKING@
HAS_IPV6          := @HAS_IPV6@
HAS_DNS_RESOLVER  := @HAS_DNS_RESOLVER@
HAS_PCAP          := @HAS_PCAP@
HAS_OPENSSL       := @HAS_OPENSSL@
HAS_SSL           := @HAS_OPENSSL@
HAS_OPENLDAP      := @HAS_OPENLDAP@
HAS_LDAP          := @HAS_OPENLDAP@
HAS_SASL          := @HAS_SASL@
HAS_SASL2         := @HAS_SASL2@
HAS_EXPAT         := @HAS_EXPAT@
HAS_REGEX         := @HAS_REGEX@
HAS_SDL           := @HAS_SDL@
HAS_PLUGINMGR     := @HAS_PLUGINMGR@
HAS_PLUGINS       := @HAS_PLUGINS@
HAS_SAMPLES       := @HAS_SAMPLES@

HAS_CYPHER        := @HAS_CYPHER@
HAS_VARTYPE       := @HAS_VARTYPE@
HAS_GUID          := @HAS_GUID@
HAS_SCRIPTS       := @HAS_SCRIPTS@
HAS_SPOOLDIR      := @HAS_SPOOLDIR@
HAS_SYSTEMLOG     := @HAS_SYSTEMLOG@
HAS_CHANNEL_UTILS := @HAS_CHANNEL_UTILS@
HAS_TTS           := @HAS_TTS@
HAS_ASN           := @HAS_ASN@
HAS_NAT           := @HAS_NAT@
HAS_STUN          := @HAS_STUN@
HAS_STUNSRVR      := @HAS_STUNSRVR@
HAS_PIPECHAN      := @HAS_PIPECHAN@
HAS_DTMF          := @HAS_DTMF@
HAS_VCARD         := @HAS_VCARD@
HAS_WAVFILE       := @HAS_WAVFILE@
HAS_SOCKS         := @HAS_SOCKS@
HAS_FTP           := @HAS_FTP@
HAS_SNMP          := @HAS_SNMP@
HAS_TELNET        := @HAS_TELNET@
HAS_CLI           := @HAS_CLI@
HAS_REMCONN       := @HAS_REMCONN@
HAS_SERIAL        := @HAS_SERIAL@
HAS_POP3SMTP      := @HAS_POP3SMTP@
HAS_AUDIO         := @HAS_AUDIO@
HAS_VIDEO         := @HAS_VIDEO@
HAS_SHM_VIDEO     := @HAS_SHM_VIDEO@
HAS_SHM_AUDIO     := @HAS_SHM_AUDIO@
HAS_PORTAUDIO     := @HAS_PORTAUDIO@
HAS_SUN_AUDIO     := @HAS_SUN_AUDIO@
HAS_VFW_CAPTURE   := @HAS_VFW_CAPTURE@
HAS_GSTREAMER     := @HAS_GSTREAMER@

HAS_VXML          := @HAS_VXML@
HAS_JABBER        := @HAS_JABBER@
HAS_XMLRPC        := @HAS_XMLRPC@
HAS_SOAP          := @HAS_SOAP@
HAS_URL           := @HAS_URL@
HAS_HTTP          := @HAS_HTTP@
HAS_HTTPFORMS     := @HAS_HTTPFORMS@
HAS_HTTPSVC       := @HAS_HTTPSVC@
HAS_SSDP          := @HAS_SSDP@
HAS_CONFIG_FILE   := @HAS_CONFIG_FILE@
HAS_VIDFILE       := @HAS_VIDFILE@
HAS_MEDIAFILE     := @HAS_MEDIAFILE@
HAS_ODBC          := @HAS_ODBC@
HAS_DIRECTSHOW    := @HAS_DIRECTSHOW@
HAS_DIRECTSOUND   := @HAS_DIRECTSOUND@
HAS_LUA           := @HAS_LUA@
HAS_V8            := @HAS_V8@

HAS_ALSA          := @HAS_ALSA@
HAS_AUDIOSHM      := @HAS_AUDIOSHM@
HAS_OSS           := @HAS_OSS@
HAS_PULSE         := @HAS_PULSE@
HAS_ESD           := @HAS_ESD@
HAS_SUNAUDIO      := @HAS_SUNAUDIO@
HAS_V4L           := @HAS_V4L@
HAS_V4L2          := @HAS_V4L2@
HAS_BSDVIDEOCAP   := @HAS_BSDVIDEOCAP@
HAS_AVC1394       := @HAS_AVC1394@
HAS_DC1394        := @HAS_DC1394@

ESD_CFLAGS  := @ESD_CFLAGS@
ESD_LIBS    := @ESD_LIBS@
V4L2_CFLAGS := @V4L2_CFLAGS@
V4L2_LIBS   := @V4L2_LIBS@
DC_CFLAGS   := @DC_CFLAGS@


# Remember where this make file is, it is the platform specific one and there
# is a corresponding platform specific include file that goes with it
PTLIB_PLATFORM_INC_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../include)


# End of ptlib_config.mak

