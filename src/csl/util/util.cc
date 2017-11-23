///
/// \file       util.cc
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \date       2015-04-24 07:33:39 -0700
///
/// \copyright  Copyright (C) 2014 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief
///

#include <base/printf.h>
#include <base/snprintf.h>
#include <csl/util/byte_array.h>
#include <csl/util/util.h>
#include <csl/util/logger.h>

using Csl::uint8_t;

Csl::string hex_string( const uint8_t *const src, const size_t size )
{
	return hex_string( ustring( src, size ) );
}

Csl::string hex_string( ustring s )
{
	static const char *const lut = "0123456789ABCDEF";
	size_t len = s.length();

	Csl::string output;
	output = Csl::sprintf( " %d bytes:", s.size() );
	output.reserve( 2 * len );

	for ( size_t i = 0; i < len; ++i )
	{
		if ( ( i%32==0 ) )
		{
			output.push_back( '\n' );
			output.append( "    " );
		}

		const uint8_t c = s[i];
		output.push_back( lut[c >> 4] );
		output.push_back( lut[c & 15] );

		// Genode has a limit of 2047 characters. So when the
		// output gets long, warn the user about this and
		// shorten the log message.

		static const size_t LOG_LIMIT = 1950;

		if ( output.size() >  LOG_LIMIT )
		{
			output += Csl::string( " ... !!! WARNING: Cut off the log message." );
			return output;
		}
	}

	return output;
}

namespace Csl
{
	using Print_buffer = Byte_array<2*2024>;

	const Csl::string vsprintf( const Csl::string &fmt, va_list args )
	{
		Print_buffer buffer;
		Genode::String_console sc( buffer.val, buffer.capacity() );
		sc.vprintf( fmt.c_str(), args );

		if ( 0 > sc.len() )
		{
			throw Csl::Formatting_error();
		}

		return buffer.str();
	}

	const Csl::string sprintf( const Csl::string &fmt, ... )
	{
		va_list args;
		va_start( args,fmt );
		string ret;

		try
		{
			ret = vsprintf( fmt, args );
		}
		catch ( ... )
		{
			va_end( args );
			throw;
		}

		va_end( args );
		return ret;
	}

	const void printf( const Csl::string &fmt, ... )
	{
		va_list args;
		va_start( args,fmt );
		Genode::vprintf( fmt.c_str(), args );
		va_end( args );

	}
}
