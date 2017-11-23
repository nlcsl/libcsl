///
/// \file       shared_settings.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-01-06
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      class to fascilitate access to shared memory.
///

#pragma once

#include <csl/util/property_sequence.h>
#include <csl/util/data_descriptor.h>

#include <base/env.h>
#include <dataspace/capability.h>
#include <base/attached_rom_dataspace.h>

#include <csl/util/assert.h>

namespace Csl
{
	class Shared_settings
	{
		protected:
			bool _valid;
		public:
			using Mem = Csl::Data_descriptor_mod;
			using Mem_ro = Csl::Data_descriptor;

			template <typename FUN>
			void safe_operation( FUN accessor )
			{
				cslassert( _valid );
				static Genode::Lock lock;
				Genode::Lock_guard<Genode::Lock> guard( lock );

				uint8_t buffer[mem().size()];
				Genode::memcpy( buffer, mem().data(), mem().size() );
				Mem_ro clone( buffer, mem().size() );
				Csl::Property_sequence p( clone );

				try
				{
					accessor( p );
				}
				catch ( ... ) {}

				Genode::memcpy( mem().data(), buffer, mem().size() );
			}

			virtual Mem mem() = 0;
			virtual Csl::Property_sequence &prop() = 0;
			virtual ~Shared_settings() {}

			virtual Genode::Dataspace_capability &cap()
			{
				static Genode::Dataspace_capability dc;
				return dc;
			}
	};

	class Shared_settings_provider: public Shared_settings
	{
		private:
			Genode::Dataspace_capability _cap;
			Mem _mem;
			Csl::Property_sequence _settings;
		public:
			explicit Shared_settings_provider( Genode::Env &env, const size_t s ):
				_cap( env.ram().alloc( s ) ),
				_mem( env.rm().attach( _cap ), s ),
				_settings( _mem )
			{
				_valid = true;
			}

			Shared_settings_provider()
			{
				_valid = false ;
			}

			Mem mem() override
			{
				cslassert( _valid );
				return _mem;
			}
			Csl::Property_sequence &prop() override
			{
				cslassert( _valid );
				return _settings;
			}

			Genode::Dataspace_capability &cap()
			{
				cslassert( _valid );
				return _cap;
			}
	};

	class Shared_settings_consumer: public Shared_settings
	{
		private:
			Mem _mem;
			Csl::Property_sequence _settings;
		public:
			explicit Shared_settings_consumer( Genode::Env &env,
			                                   Genode::Dataspace_capability cap )
			{
				_valid = true;
				auto addr = env.rm().attach( cap );
				Genode::Dataspace_client client( cap );
				_mem = Mem( addr, client.size() ) ;
				_settings = Csl::Property_sequence( _mem );
			}

			Shared_settings_consumer()
			{
				_valid = false;
			}

			Mem mem() override
			{
				cslassert( _valid );
				return _mem;
			};
			Csl::Property_sequence &prop() override
			{
				cslassert( _valid );
				return _settings;
			}

	};
}

