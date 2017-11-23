///
/// \file       hash.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-05-10
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief Implementation of non-cryptographic hash function current
///        implementation is the DJB hash. Sight modification of the
///        reference implementation for usage reasons.
///

#pragma once

#include <csl/util/stdint.h>

using Csl::size_t;

// modified version of http://www.cse.yorku.ca/~oz/hash.html
inline size_t  djb2hash( Csl::uint8_t *str, const Csl::size_t len )
{
	Csl::size_t hash = 5381;

	for ( Csl::size_t i = 0; i < len; ++i )
	{
		Csl::uint32_t c = str[i];
		hash = ( ( hash << 5 ) + hash ) + c;
	}

	return hash;
}


namespace Csl
{
	template <typename T>
	struct hash
	{
		Csl::size_t operator()( const T &t ) const
		{
			return djb2hash( ( Csl::uint8_t * ) &t, sizeof( T ) );
		}
	};

};


