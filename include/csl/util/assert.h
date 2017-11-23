
///
/// \file       assert.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-04-20
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Implementtions of CSL assertions
///

#pragma once

#include <csl/util/logger.h>
#include <base/env.h>
#include <parent/parent.h>

#define CSLASSERT

#ifdef CSLASSERT

#define cslassert( expression ) {							\
if( ! ( expression ) ) {								\
	ALOG("assertion failed at %s:%i: '%s'", __FILE__, __LINE__ , #expression);	\
}}


#else

#define cslassert( expression )

#endif

