///
/// \file       util.h
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \date       2015-04-21 04:45:16 -0700
///
/// \copyright  Copyright (C) 2014 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief
///

#pragma once

#include <csl/util/string.h>

extern Csl::string hex_string( const Csl::uint8_t *const src,
                               const Csl::size_t size );
extern Csl::string hex_string( ustring s );

namespace Csl
{
	class Non_copyable
	{

		protected:
			Non_copyable() {}
			~Non_copyable() {}

		public:
			Non_copyable( const Non_copyable & ) = delete;
			Non_copyable( const Non_copyable && ) = delete;
			Non_copyable &operator= ( const Non_copyable & ) = delete;
	};
}
