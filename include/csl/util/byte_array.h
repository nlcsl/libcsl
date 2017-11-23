///
/// \file       byte_array.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-01-20
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief Storage template for null terminated strings, which should
///        be nullified before and after use. This class is commonly
///        used with plain-old-c functions that require null
///        terminated strings.
///

#pragma once

#include <csl/util/exception.h>
#include <csl/util/string.h>
#include <csl/util/fthrow.h>


namespace Csl
{
	template<size_t MAX_SIZE = 1024, typename C = char>
	struct Byte_array
	{
		C val[MAX_SIZE];

		static const size_t SIZE = MAX_SIZE;

		void nullify()
		{
			Genode::memset( val, 0, sizeof( val ) );
		}

		size_t capacity() const
		{
			// last array_element is saved for the 0 value.
			return sizeof( val ) - 1;
		}

		Byte_array()
		{
			nullify();
		}

		Byte_array( const Csl::Basic_string<C> &s ): Byte_array()
		{
			if ( capacity() < s.length() )
			{
				fthrow<Exception>( "Insufficient space to store %i bytes", s.length() );
			}

			Genode::memcpy( val, const_cast<C *>( s.data() ), s.length() );
		}
		~Byte_array()
		{
			nullify();
		}
		Csl::string str() const
		{
			return Csl::string( val );
		}
	};
}
