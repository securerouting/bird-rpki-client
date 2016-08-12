/*
 * This file is part of BIRD-RPKI-Client.
 *
 * This software was originally based off the BIRD-RTRLib-CLI by
 * written by Mehmet Ceyran, in cooperation with: CST group, Freie
 * Universitaet Berlin Website:
 * https://github.com/rtrlib/BIRD-RTRLib-CLI
 *
 * It has been heavily modified by Parsons, Inc. The modifications and
 * additions are licensed, as the original, under the LGPLv3.  You
 * should have received a copy of the GNU Lesser General Public
 * License along with BIRD-RTRLib-CLI; see the file COPYING.
 *
 * BIRD-RPKI-Client modified by Michael Baer, Parsons, Inc (c)
 * 2014-2016
 *
 *
 * Excerpts from the original BIRD-RTRLib-CLI license statement
 * follows:
 * BIRD-RTRLib-CLI is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 */


#ifndef BIRD_RTRLIB_CLI__CLI_H
#define	BIRD_RTRLIB_CLI__CLI_H

#include "config.h"

/**
 * Parses the specified command line into the specified application config.
 * @param
 * @param
 * @param
 * @return
 */
int parse_cli(int, char **, struct config *);

#endif
