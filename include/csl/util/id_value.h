///
/// \file       id_value.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-05-27
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      TODO
///

#pragma once

#include <csl/util/list.h>
#include <csl/util/stdint.h>

namespace Csl
{
	template<typename VALUE_TYPE, typename ID_TYPE=Csl::uint64_t>
	class Id_value_store
	{
		public:
			using Value_type = VALUE_TYPE;
			using Id_type = ID_TYPE;

			EXCEPTION( Not_found );
		private:
			struct  Id_value
			{
				Id_type id;
				Value_type *value;
			};

			List<Id_value > _list;

			Id_value _find( const Id_type &id )
			{
				for ( auto kv: _list )
				{
					if ( kv.id == id )
					{
						return kv;
					}
				}

				throw Not_found();

			}
		public:
			Id_value_store() {};

			void add( const Id_type &id, Value_type *val )
			{
				Id_value id_value {id, val};
				_list.push_back( id_value );
			}

			Value_type *erase( const Id_type &id )
			{

				for ( auto it = _list.begin(); it != _list.end(); ++it )
				{
					if ( it->id == id )
					{
						_list.erase( it );
						return it->value;
					}
				}

				return nullptr;
			}

			Value_type *erase( const Value_type &value )
			{
				for ( auto it = _list.begin(); it != _list.end(); ++it )
				{
					if ( it->value == &value )
					{
						_list.erase( it );
						return it->value;
					}
				}

				return nullptr;
			}

			const Value_type *find( const Id_type &id ) const
			{
				try
				{
					return _find( id ).value;
				}
				catch ( const Not_found &e )
				{
					return nullptr;
				}
			}

			Value_type *find( const Id_type &id )
			{
				try
				{
					return _find( id ).value;
				}
				catch ( const Not_found &e )
				{
					return nullptr;
				}
			}

			size_t size() const
			{
				return _list.size();
			}

			List<Value_type *> all()
			{
				List<Value_type *> res;

				for ( auto item : _list )
				{
					res.push_back( item.value );
				}

				return res;
			}

	};
}

