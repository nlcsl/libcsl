///
/// \file       factory_template.h
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \date       2015-12-21 11:00:12 +0100
///
/// \copyright  Copyright (C) 2015 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief
///

#pragma once

template <typename B, typename... Ts>
struct Factory_template
{
	static B *create( Csl::uint8_t id, const Csl::Data_descriptor dd )
	{
		return nullptr;
	}
};

template <typename B, typename T, typename... Ts>
struct Factory_template<B, T, Ts...> : Factory_template<B, Ts...>
{
	static B *create( Csl::uint8_t id, const Csl::Data_descriptor dd )
	{
		if ( id == T::PLT )
		{
			return new T( dd );
		}

		return Factory_template<B, Ts...>::create( id, dd );
	}
};

