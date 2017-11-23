///
/// \file       string_util.h
/// \author     Boris Mulder <boris.mulder@nlcsl.com>
/// \date       24-02-2017
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief		Convenience functions for strings
///

#pragma once

#include <csl/util/string.h>
#include <csl/util/list.h>

namespace Csl
{

	List<string> split( const string &str, const string &delim,
	                    bool include_empty_strings = true );
	List<string> split( const string &str, const char delim,
	                    bool include_empty_strings = true );

	//string replace(string &original, string &old, string &new);

}
