///
/// \file       entropy.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-08-23
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief 
///

#pragma once

#include <csl/util/data_descriptor.h>
#include <csl/util/stdint.h>

#include <jitterentropy.h>

namespace Csl
{
	class Entropy
	{
		private:
			struct rand_data *_ec;
			bool _valid;

			void _check_validity()
			{
				if ( not _valid )
				{
					log_and_throw<Csl::Exception>( "Attempt to use invalid entropy structure" );
				}
			}

			bool _init( Genode::Allocator &alloc )
			{
				jitterentropy_init( alloc );

				const int err = jent_entropy_init();

				if ( err )
				{
					ELOG( "Unable to initialize jitter entropy" );
					return false;
				}

				_ec = jent_entropy_collector_alloc( 0,0 );

				if ( nullptr == _ec )
				{
					ELOG( "Unable to allocate entropy collector" );
					return false;
				}

				return true;
			}

		public:

			/// Get entropy
			///
			/// \param dd the data descriptor to fill with entropy
			///
			void get( const Data_descriptor_mod &dd )
			{
				_check_validity();
				const size_t entropy_bytes = jent_read_entropy( _ec, ( char * ) dd.data(),
				                             dd.size() );

				if ( entropy_bytes != dd.size() )
				{
					throw Csl::Exception( "Unable to gather the requested amount of entropy" );
				}
			}

			Entropy( Genode::Allocator &alloc ): _ec( nullptr ), _valid( _init( alloc ) ) {}

			~Entropy()
			{
				if ( nullptr != _ec )
				{
					jent_entropy_collector_free( _ec );
				}
			}
	};
}

