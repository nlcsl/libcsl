///
/// \file       main.cc
/// \author     Boris Mulder <boris.mulder@nlcsl.com>
/// \date       2017-03-10
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      random hello world
///

#include <csl/crypto/entropy.h>
#include <csl/util/logger.h>
#include <csl/util/data_descriptor.h>

#include <base/component.h>
#include <base/heap.h>

namespace Hello
{
	struct Main;
}

struct Hello::Main
{
	Genode::Env &_env;
	Genode::Heap _heap;

	Main( Genode::Env &env ) : _env( env ), _heap( _env.ram(), _env.rm() )
	{
		try
		{
			Csl::Entropy rng( _heap );
			Csl::uint8_t buf[3];
			Csl::Data_descriptor_mod ddm( buf, sizeof( buf ) );
			rng.get( ddm );
			Genode::log( "random bytes: ", buf[0], " ", buf[1], " ", buf[2] );
			Genode::log( "test finished." );
		}
		catch ( const Csl::Exception &e )
		{
			Genode::error( "Caught exception: ", e.what() );
		}
		catch ( ... )
		{
			Genode::error( "Unknown exception" );
			throw;
		}
	}
};

Genode::size_t Component::stack_size()
{
	return 64*1024;
}

void Component::construct( Genode::Env &env )
{
	static Hello::Main main( env );
}
