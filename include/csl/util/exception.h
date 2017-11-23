///
/// \file       exception.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2015-12-21 12:20:18 +0100
///
/// \copyright  Copyright (C) 2015 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Exception class
///

#pragma once

// Csl includes
#include <csl/util/stdint.h>

//Genode includes
#include <util/string.h>

namespace Csl
{
	class Exception
	{
		private:
			static const size_t LEN = 1024;
			char _what[ LEN ];
		public:
			Exception( const char *const w )
			{
				Genode::memset( _what, 0, LEN );
				Genode::strncpy( _what, w, LEN );
			}

			Exception() {}

			virtual const char *const what() const
			{
				return _what;
			}
			virtual ~Exception() {}
	};
} // namespace Csl

// Convencience #define's to make an exception subclass
#define EXCEPTION( E ) class E: public Csl::Exception{ public: using Csl::Exception::Exception;  }
#define EXCEPTIONS( E, S ) class E: public S{public: using S::S; }

// Some common exception classes
namespace Csl
{
	EXCEPTION( Out_of_range );
	EXCEPTION( Empty );
}

