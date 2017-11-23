///
/// \file       csl/util/logger.cc
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2017-02-24
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      init logging
///
#include <csl/util/logger.h>

namespace Csl {
	void init_logging( const Genode::Xml_node &rootnode )
	{
		try
		{
			Genode::Xml_node logging = Csl::Xml_path( "csl/logging" ).get_node( rootnode );

			logging.for_each_sub_node( "logger",
			                           [&]( Genode::Xml_node lcfg )
			{
				Csl::string name, level;

				try
				{

					name = get_attribute_val( lcfg, "name" );
					level = get_attribute_val( lcfg, "level" );

					Log_factory::instance()
					.get( name.c_str() )
					.level( Log_helper::str_level( level.c_str() ) );
				}
				catch ( const Log_helper::Log_no_such_log_level &l )
				{
					Genode::warning( "Unknown log level: ", level.c_str() );
				}
				catch ( const Log_factory::Log_manager_logger_not_found_exception &l )
				{
					Genode::warning( "Unknown log manager: ", name.c_str() );
				}
				catch ( ... )
				{
					Genode::error( "Error in your logging configuration" );
				}

			} );

			try
			{
				Csl::string filter = get_attribute_val( logging, "filter_duplicate_messages" );

				if ( filter == Csl::string( "true" ) )
				{
					Output_repeat_filter::instance().enable();
				}
			}
			catch ( ... )
			{
				// attribute not set
			}
		}
		catch ( ... )
		{
			// No logging configuration available
		}
	}
}
