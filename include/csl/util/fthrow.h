///
/// \file       fthrow.h
/// \author     Menno Valkema <valkema@nlcsl.com>
/// \date       2017-02-24 04:45:16 -0700
///
/// \copyright  Copyright (C) 2014 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief		Workaround as constructor forwarding does not seem to support
/// 			variable arguments.

#pragma once

#include <csl/util/string.h>

///
/// Throw exception E with format string
///
/// \param fmt the format string
///
template<class E>
inline void fthrow( const char *fmt, ... )
{
	va_list args;
	va_start( args,fmt );
	auto w = Csl::vsprintf( fmt, args );
	va_end( args );
	throw E( w.c_str() );

}
