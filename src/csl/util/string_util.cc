///
/// \file       csl/util/string_util.cc
///	\author     Boris Mulder <boris.mulder@nlcsl.com>
/// \date       17-03-2017
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///

#include <csl/util/string_util.h>

namespace Csl
{

	List<string> split( const string &str, const string &delim,
	                    bool include_empty_strings )
	{
		List<string> res;
		size_t curr = 0;
		size_t next = 0;
		size_t npos = str.npos;

		do
		{
			next = str.find( delim, curr );

			size_t len = ( next == npos ) ? str.size() - curr : next - curr;

			if ( include_empty_strings || len != 0 )
			{ res.push_back( str.substr( curr, len ) ); }

			curr = next + delim.size();
		}
		while ( next != npos );

		return res;
	}

	List<string> split( const string &str, const char delim,
	                    bool include_empty_strings )
	{
		string temp( &delim, 1 );
		return split( str, temp, include_empty_strings );
	}
}
