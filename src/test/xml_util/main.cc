///
/// \file       test/xml_util/main.cc
/// \author     Boris Mulder <boris.mulder@nlcsl.com>
/// \date       21-02-2017
///
/// \copyright  Copyright (C) 2014 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief		tests for util/xml_util.h>
///

// Genode includes
#include <base/component.h>
#include <base/heap.h>
#include <base/attached_rom_dataspace.h>

// CSL includes
#include <csl/util/xml_util.h>
#include <csl/util/logger.h>
#include <csl/util/assert.h>

namespace Xml_util_test
{

	class Main
	{
		private:
			Genode::Env &_env;
			Genode::Attached_rom_dataspace config;

		public:
			Main( Genode::Env &env ) : _env( env ), config( _env, "config" )
			{
				Genode::Xml_node config_root = config.xml();

				try
				{
					Genode::Xml_node var =
					    Csl::Xml_path( "x:part=2/y:a=aa:b=&equalsbee/z:d=dee/var" )
					    .get_node( config_root );
					ILOG( "Test 1: %s %s", Csl::get_attribute_val( var, "a" ).c_str(),
					      Csl::get_attribute_val( var, "b" ).c_str() );
					ILOG( "Test 1 succeeded" );
				}
				catch ( Csl::Exception &e )
				{
					ELOG( "Test 1: got exception: %s", e.what() );
				}
				catch ( ... )
				{
					ELOG( "Test 1: caught unknown exception" );
				}

				try
				{
					Csl::Xml_path( "x:part=1/y:a=aa:b=&equalsbee/z:var" ).get_node( config_root );
					ELOG( "Test 2: incorrect path succeeded" );
				}
				catch ( Csl::Nonexistent_sub_node )
				{
					ILOG( "Test 2 succeeded" );
				}
				catch ( Csl::Exception &e )
				{
					ELOG( "Test 2: got exception: %s", e.what() );
				}
				catch ( ... )
				{
					ELOG( "Test 2: unknown error" );
				}

				char buf[1024];

				try
				{
					Csl::Xml_path( "a:x=1/b:y=2:z=3/c" )
					.create_node( buf, sizeof( buf ) );
					ILOG( "Test 3:\n%s", buf );
					ILOG( "Test 3 succeeded" );
				}
				catch ( Csl::Exception &e )
				{
					ELOG( "part 3: got exception: %s", e.what() );
				}
				catch ( ... )
				{
					ELOG( "part 3: caught unknown exception" );
				}

				ILOG( "xml_util test completed." );
			}
	};

}

Genode::size_t Component::stack_size()
{
	return 64*1024;
}

void Component::construct( Genode::Env &env )
{
	static Xml_util_test::Main main( env );
}
