# Copyright (C) 2007-2009 LuaDist.
# Created by Peter Drahoš
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the COPYRIGHT file distributed with LuaDist.
# Please note that the package source code is licensed under its own license.

PROJECT(slncrypto C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
INCLUDE(dist.cmake)

# Build
ADD_LUA_MODULE(crypto slncrypt.c crypto.def)

# Install all files and documentation
INSTALL (TARGETS crypto DESTINATION ${INSTALL_CMOD})
INSTALL (FILES cryptest DESTINATION ${INSTALL_DATA})
