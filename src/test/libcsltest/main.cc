///
/// \file       main.cc
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2017-02-24
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Hello World to check if libcsl builds
///

#include <csl/util/logger.h>
#include <base/component.h>

namespace Hello
{
	struct Main;
}

struct Hello::Main
{
	Genode::Env &env;

	Main( Genode::Env &env ) : env( env )
	{
		ILOG( "hello world." );
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
