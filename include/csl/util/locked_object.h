///
/// \file       locked_object.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2015-07-27 11:48:11 +0200
///
/// \copyright  Copyright (C) 2015 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Make an object only accessible throught a lock.
///

#pragma once

#include <base/lock.h>
#include <base/lock_guard.h>

/// Convenience template for variables that are shared between threads
/// and should be locked when used. Note that this doesn't guarantee
/// the object can't be copied out of the locked_object struct,
/// however it offers convenient access using a handler.
///
/// Example:
/// \verbatim
///
/// Csl::locked_object<Sp::Sps> _spd; // locked object.
/// _spd.access([](Sp::Sps &spd){  // use access to guarantee treatsafe operations on spd.
///   spd.some_action();
/// })
///
/// \endverbatim
///

namespace Csl
{
	template <typename O>
	struct locked_object
	{
		private:
			O _o;
			Genode::Lock _lock;

			// Copying a locked object is funny. This means you either
			// don't need a lock, or you didn't intend to copy it in the
			// first place. Thus we explicitly disable this.
			locked_object( const locked_object &o );
			locked_object operator=( const locked_object &o );
		public:
			typedef O type;

			locked_object( const O &o ):
				_o( o ), _lock()
			{}

			locked_object():
				_o(), _lock()
			{}

			template<typename R, typename FUN>
			R access( FUN handle )
			{
				Genode::Lock_guard<Genode::Lock> guard( _lock );
				return handle( _o );
			}
	};
} //  namespace Csl

