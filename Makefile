# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.3

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/baerm/snmp/routesec/bird/bgpsec-tools/bgpsec-bird-client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/baerm/snmp/routesec/bird/bgpsec-tools/bgpsec-bird-client

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/ccmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/baerm/snmp/routesec/bird/bgpsec-tools/bgpsec-bird-client/CMakeFiles /home/baerm/snmp/routesec/bird/bgpsec-tools/bgpsec-bird-client/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/baerm/snmp/routesec/bird/bgpsec-tools/bgpsec-bird-client/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named bird-rpki-client

# Build rule for target.
bird-rpki-client: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 bird-rpki-client
.PHONY : bird-rpki-client

# fast build rule for target.
bird-rpki-client/fast:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/build
.PHONY : bird-rpki-client/fast

bird-rpki-client.o: bird-rpki-client.c.o

.PHONY : bird-rpki-client.o

# target to build an object file
bird-rpki-client.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/bird-rpki-client.c.o
.PHONY : bird-rpki-client.c.o

bird-rpki-client.i: bird-rpki-client.c.i

.PHONY : bird-rpki-client.i

# target to preprocess a source file
bird-rpki-client.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/bird-rpki-client.c.i
.PHONY : bird-rpki-client.c.i

bird-rpki-client.s: bird-rpki-client.c.s

.PHONY : bird-rpki-client.s

# target to generate assembly for a file
bird-rpki-client.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/bird-rpki-client.c.s
.PHONY : bird-rpki-client.c.s

cli.o: cli.c.o

.PHONY : cli.o

# target to build an object file
cli.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/cli.c.o
.PHONY : cli.c.o

cli.i: cli.c.i

.PHONY : cli.i

# target to preprocess a source file
cli.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/cli.c.i
.PHONY : cli.c.i

cli.s: cli.c.s

.PHONY : cli.s

# target to generate assembly for a file
cli.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/cli.c.s
.PHONY : cli.c.s

config.o: config.c.o

.PHONY : config.o

# target to build an object file
config.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/config.c.o
.PHONY : config.c.o

config.i: config.c.i

.PHONY : config.i

# target to preprocess a source file
config.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/config.c.i
.PHONY : config.c.i

config.s: config.c.s

.PHONY : config.s

# target to generate assembly for a file
config.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/config.c.s
.PHONY : config.c.s

rpkiRtrCacheServerTable.o: rpkiRtrCacheServerTable.c.o

.PHONY : rpkiRtrCacheServerTable.o

# target to build an object file
rpkiRtrCacheServerTable.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable.c.o
.PHONY : rpkiRtrCacheServerTable.c.o

rpkiRtrCacheServerTable.i: rpkiRtrCacheServerTable.c.i

.PHONY : rpkiRtrCacheServerTable.i

# target to preprocess a source file
rpkiRtrCacheServerTable.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable.c.i
.PHONY : rpkiRtrCacheServerTable.c.i

rpkiRtrCacheServerTable.s: rpkiRtrCacheServerTable.c.s

.PHONY : rpkiRtrCacheServerTable.s

# target to generate assembly for a file
rpkiRtrCacheServerTable.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable.c.s
.PHONY : rpkiRtrCacheServerTable.c.s

rpkiRtrCacheServerTable_data_access.o: rpkiRtrCacheServerTable_data_access.c.o

.PHONY : rpkiRtrCacheServerTable_data_access.o

# target to build an object file
rpkiRtrCacheServerTable_data_access.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_access.c.o
.PHONY : rpkiRtrCacheServerTable_data_access.c.o

rpkiRtrCacheServerTable_data_access.i: rpkiRtrCacheServerTable_data_access.c.i

.PHONY : rpkiRtrCacheServerTable_data_access.i

# target to preprocess a source file
rpkiRtrCacheServerTable_data_access.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_access.c.i
.PHONY : rpkiRtrCacheServerTable_data_access.c.i

rpkiRtrCacheServerTable_data_access.s: rpkiRtrCacheServerTable_data_access.c.s

.PHONY : rpkiRtrCacheServerTable_data_access.s

# target to generate assembly for a file
rpkiRtrCacheServerTable_data_access.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_access.c.s
.PHONY : rpkiRtrCacheServerTable_data_access.c.s

rpkiRtrCacheServerTable_data_get.o: rpkiRtrCacheServerTable_data_get.c.o

.PHONY : rpkiRtrCacheServerTable_data_get.o

# target to build an object file
rpkiRtrCacheServerTable_data_get.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_get.c.o
.PHONY : rpkiRtrCacheServerTable_data_get.c.o

rpkiRtrCacheServerTable_data_get.i: rpkiRtrCacheServerTable_data_get.c.i

.PHONY : rpkiRtrCacheServerTable_data_get.i

# target to preprocess a source file
rpkiRtrCacheServerTable_data_get.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_get.c.i
.PHONY : rpkiRtrCacheServerTable_data_get.c.i

rpkiRtrCacheServerTable_data_get.s: rpkiRtrCacheServerTable_data_get.c.s

.PHONY : rpkiRtrCacheServerTable_data_get.s

# target to generate assembly for a file
rpkiRtrCacheServerTable_data_get.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_get.c.s
.PHONY : rpkiRtrCacheServerTable_data_get.c.s

rpkiRtrCacheServerTable_data_set.o: rpkiRtrCacheServerTable_data_set.c.o

.PHONY : rpkiRtrCacheServerTable_data_set.o

# target to build an object file
rpkiRtrCacheServerTable_data_set.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_set.c.o
.PHONY : rpkiRtrCacheServerTable_data_set.c.o

rpkiRtrCacheServerTable_data_set.i: rpkiRtrCacheServerTable_data_set.c.i

.PHONY : rpkiRtrCacheServerTable_data_set.i

# target to preprocess a source file
rpkiRtrCacheServerTable_data_set.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_set.c.i
.PHONY : rpkiRtrCacheServerTable_data_set.c.i

rpkiRtrCacheServerTable_data_set.s: rpkiRtrCacheServerTable_data_set.c.s

.PHONY : rpkiRtrCacheServerTable_data_set.s

# target to generate assembly for a file
rpkiRtrCacheServerTable_data_set.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_data_set.c.s
.PHONY : rpkiRtrCacheServerTable_data_set.c.s

rpkiRtrCacheServerTable_interface.o: rpkiRtrCacheServerTable_interface.c.o

.PHONY : rpkiRtrCacheServerTable_interface.o

# target to build an object file
rpkiRtrCacheServerTable_interface.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_interface.c.o
.PHONY : rpkiRtrCacheServerTable_interface.c.o

rpkiRtrCacheServerTable_interface.i: rpkiRtrCacheServerTable_interface.c.i

.PHONY : rpkiRtrCacheServerTable_interface.i

# target to preprocess a source file
rpkiRtrCacheServerTable_interface.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_interface.c.i
.PHONY : rpkiRtrCacheServerTable_interface.c.i

rpkiRtrCacheServerTable_interface.s: rpkiRtrCacheServerTable_interface.c.s

.PHONY : rpkiRtrCacheServerTable_interface.s

# target to generate assembly for a file
rpkiRtrCacheServerTable_interface.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrCacheServerTable_interface.c.s
.PHONY : rpkiRtrCacheServerTable_interface.c.s

rpkiRtrPrefixOriginTable.o: rpkiRtrPrefixOriginTable.c.o

.PHONY : rpkiRtrPrefixOriginTable.o

# target to build an object file
rpkiRtrPrefixOriginTable.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable.c.o
.PHONY : rpkiRtrPrefixOriginTable.c.o

rpkiRtrPrefixOriginTable.i: rpkiRtrPrefixOriginTable.c.i

.PHONY : rpkiRtrPrefixOriginTable.i

# target to preprocess a source file
rpkiRtrPrefixOriginTable.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable.c.i
.PHONY : rpkiRtrPrefixOriginTable.c.i

rpkiRtrPrefixOriginTable.s: rpkiRtrPrefixOriginTable.c.s

.PHONY : rpkiRtrPrefixOriginTable.s

# target to generate assembly for a file
rpkiRtrPrefixOriginTable.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable.c.s
.PHONY : rpkiRtrPrefixOriginTable.c.s

rpkiRtrPrefixOriginTable_data_access.o: rpkiRtrPrefixOriginTable_data_access.c.o

.PHONY : rpkiRtrPrefixOriginTable_data_access.o

# target to build an object file
rpkiRtrPrefixOriginTable_data_access.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_access.c.o
.PHONY : rpkiRtrPrefixOriginTable_data_access.c.o

rpkiRtrPrefixOriginTable_data_access.i: rpkiRtrPrefixOriginTable_data_access.c.i

.PHONY : rpkiRtrPrefixOriginTable_data_access.i

# target to preprocess a source file
rpkiRtrPrefixOriginTable_data_access.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_access.c.i
.PHONY : rpkiRtrPrefixOriginTable_data_access.c.i

rpkiRtrPrefixOriginTable_data_access.s: rpkiRtrPrefixOriginTable_data_access.c.s

.PHONY : rpkiRtrPrefixOriginTable_data_access.s

# target to generate assembly for a file
rpkiRtrPrefixOriginTable_data_access.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_access.c.s
.PHONY : rpkiRtrPrefixOriginTable_data_access.c.s

rpkiRtrPrefixOriginTable_data_get.o: rpkiRtrPrefixOriginTable_data_get.c.o

.PHONY : rpkiRtrPrefixOriginTable_data_get.o

# target to build an object file
rpkiRtrPrefixOriginTable_data_get.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_get.c.o
.PHONY : rpkiRtrPrefixOriginTable_data_get.c.o

rpkiRtrPrefixOriginTable_data_get.i: rpkiRtrPrefixOriginTable_data_get.c.i

.PHONY : rpkiRtrPrefixOriginTable_data_get.i

# target to preprocess a source file
rpkiRtrPrefixOriginTable_data_get.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_get.c.i
.PHONY : rpkiRtrPrefixOriginTable_data_get.c.i

rpkiRtrPrefixOriginTable_data_get.s: rpkiRtrPrefixOriginTable_data_get.c.s

.PHONY : rpkiRtrPrefixOriginTable_data_get.s

# target to generate assembly for a file
rpkiRtrPrefixOriginTable_data_get.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_get.c.s
.PHONY : rpkiRtrPrefixOriginTable_data_get.c.s

rpkiRtrPrefixOriginTable_data_set.o: rpkiRtrPrefixOriginTable_data_set.c.o

.PHONY : rpkiRtrPrefixOriginTable_data_set.o

# target to build an object file
rpkiRtrPrefixOriginTable_data_set.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_set.c.o
.PHONY : rpkiRtrPrefixOriginTable_data_set.c.o

rpkiRtrPrefixOriginTable_data_set.i: rpkiRtrPrefixOriginTable_data_set.c.i

.PHONY : rpkiRtrPrefixOriginTable_data_set.i

# target to preprocess a source file
rpkiRtrPrefixOriginTable_data_set.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_set.c.i
.PHONY : rpkiRtrPrefixOriginTable_data_set.c.i

rpkiRtrPrefixOriginTable_data_set.s: rpkiRtrPrefixOriginTable_data_set.c.s

.PHONY : rpkiRtrPrefixOriginTable_data_set.s

# target to generate assembly for a file
rpkiRtrPrefixOriginTable_data_set.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_data_set.c.s
.PHONY : rpkiRtrPrefixOriginTable_data_set.c.s

rpkiRtrPrefixOriginTable_interface.o: rpkiRtrPrefixOriginTable_interface.c.o

.PHONY : rpkiRtrPrefixOriginTable_interface.o

# target to build an object file
rpkiRtrPrefixOriginTable_interface.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_interface.c.o
.PHONY : rpkiRtrPrefixOriginTable_interface.c.o

rpkiRtrPrefixOriginTable_interface.i: rpkiRtrPrefixOriginTable_interface.c.i

.PHONY : rpkiRtrPrefixOriginTable_interface.i

# target to preprocess a source file
rpkiRtrPrefixOriginTable_interface.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_interface.c.i
.PHONY : rpkiRtrPrefixOriginTable_interface.c.i

rpkiRtrPrefixOriginTable_interface.s: rpkiRtrPrefixOriginTable_interface.c.s

.PHONY : rpkiRtrPrefixOriginTable_interface.s

# target to generate assembly for a file
rpkiRtrPrefixOriginTable_interface.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtrPrefixOriginTable_interface.c.s
.PHONY : rpkiRtrPrefixOriginTable_interface.c.s

rpkiRtr_subagent.o: rpkiRtr_subagent.c.o

.PHONY : rpkiRtr_subagent.o

# target to build an object file
rpkiRtr_subagent.c.o:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtr_subagent.c.o
.PHONY : rpkiRtr_subagent.c.o

rpkiRtr_subagent.i: rpkiRtr_subagent.c.i

.PHONY : rpkiRtr_subagent.i

# target to preprocess a source file
rpkiRtr_subagent.c.i:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtr_subagent.c.i
.PHONY : rpkiRtr_subagent.c.i

rpkiRtr_subagent.s: rpkiRtr_subagent.c.s

.PHONY : rpkiRtr_subagent.s

# target to generate assembly for a file
rpkiRtr_subagent.c.s:
	$(MAKE) -f CMakeFiles/bird-rpki-client.dir/build.make CMakeFiles/bird-rpki-client.dir/rpkiRtr_subagent.c.s
.PHONY : rpkiRtr_subagent.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... bird-rpki-client"
	@echo "... bird-rpki-client.o"
	@echo "... bird-rpki-client.i"
	@echo "... bird-rpki-client.s"
	@echo "... cli.o"
	@echo "... cli.i"
	@echo "... cli.s"
	@echo "... config.o"
	@echo "... config.i"
	@echo "... config.s"
	@echo "... rpkiRtrCacheServerTable.o"
	@echo "... rpkiRtrCacheServerTable.i"
	@echo "... rpkiRtrCacheServerTable.s"
	@echo "... rpkiRtrCacheServerTable_data_access.o"
	@echo "... rpkiRtrCacheServerTable_data_access.i"
	@echo "... rpkiRtrCacheServerTable_data_access.s"
	@echo "... rpkiRtrCacheServerTable_data_get.o"
	@echo "... rpkiRtrCacheServerTable_data_get.i"
	@echo "... rpkiRtrCacheServerTable_data_get.s"
	@echo "... rpkiRtrCacheServerTable_data_set.o"
	@echo "... rpkiRtrCacheServerTable_data_set.i"
	@echo "... rpkiRtrCacheServerTable_data_set.s"
	@echo "... rpkiRtrCacheServerTable_interface.o"
	@echo "... rpkiRtrCacheServerTable_interface.i"
	@echo "... rpkiRtrCacheServerTable_interface.s"
	@echo "... rpkiRtrPrefixOriginTable.o"
	@echo "... rpkiRtrPrefixOriginTable.i"
	@echo "... rpkiRtrPrefixOriginTable.s"
	@echo "... rpkiRtrPrefixOriginTable_data_access.o"
	@echo "... rpkiRtrPrefixOriginTable_data_access.i"
	@echo "... rpkiRtrPrefixOriginTable_data_access.s"
	@echo "... rpkiRtrPrefixOriginTable_data_get.o"
	@echo "... rpkiRtrPrefixOriginTable_data_get.i"
	@echo "... rpkiRtrPrefixOriginTable_data_get.s"
	@echo "... rpkiRtrPrefixOriginTable_data_set.o"
	@echo "... rpkiRtrPrefixOriginTable_data_set.i"
	@echo "... rpkiRtrPrefixOriginTable_data_set.s"
	@echo "... rpkiRtrPrefixOriginTable_interface.o"
	@echo "... rpkiRtrPrefixOriginTable_interface.i"
	@echo "... rpkiRtrPrefixOriginTable_interface.s"
	@echo "... rpkiRtr_subagent.o"
	@echo "... rpkiRtr_subagent.i"
	@echo "... rpkiRtr_subagent.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

