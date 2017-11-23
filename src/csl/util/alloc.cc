///
/// \file       alloc.cc
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-05-10
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      not STL allocators
///

#include <base/env.h>
#include <csl/util/stdint.h>

struct bad_alloc {};

using Csl::size_t;

void *operator new( size_t n ) throw( bad_alloc )
{
	void *ret;
	Genode::env()->heap()->alloc( n, &ret );

	if ( nullptr == ret )
	{
		throw bad_alloc();
	}

	return ret;
}

void *operator new[]( size_t n ) throw( bad_alloc )
{
	void *ret;
	Genode::env()->heap()->alloc( n, &ret );

	if ( nullptr == ret )
	{
		throw bad_alloc();
	}

	return ret;
}

void operator delete( void *p ) throw()
{
	Genode::env()->heap()->free( p, 0 );
}
void operator delete[]( void *p ) throw()
{
	Genode::env()->heap()->free( p, 0 );
}

