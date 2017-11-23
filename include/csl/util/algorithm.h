///
/// \file       algorithm.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-05-10
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Some basic algorithms
///

#pragma once

namespace Csl
{
	template <typename T>
	T min( const T &a, const T &b )
	{
		return a < b ? a : b;
	}

	template <typename T>
	T max( const T &a, const T &b )
	{
		return a > b ? a : b;
	}
}


