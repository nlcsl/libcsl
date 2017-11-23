///
/// \file       ptr.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-01-28
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Contains CSL smart pointers.
///             For now merely referencing pointers from std-namespace.
///

#pragma once
namespace Csl
{
	template <typename T>
	class unique_ptr
	{
		public:
			using Type = T;
			using Pointer = Type *;

			unique_ptr( const unique_ptr &other );
		private:
			Pointer _ptr;
		public:
			unique_ptr( Pointer ptr ): _ptr( ptr ) {}
			unique_ptr(): _ptr( nullptr ) {}

			void reset( Pointer ptr = Pointer() )
			{
				if ( nullptr != _ptr )
				{
					delete _ptr;
				}

				_ptr = ptr;
			}

			Pointer operator->() const
			{
				return _ptr;
			}
			Pointer get() const
			{
				return _ptr;
			}

			Type &operator*()
			{
				return *_ptr;
			}
			const Type &operator*() const
			{
				return *_ptr;
			}

			unique_ptr &operator=( unique_ptr rhs )
			{
				_ptr = rhs._ptr;
				rhs._ptr = nullptr;
				return *this;
			}

			unique_ptr( unique_ptr &&other ): _ptr( other._ptr )
			{
				other._ptr = nullptr;
			}

			~unique_ptr()
			{
				if ( nullptr != _ptr )
				{
					delete _ptr;
				}
			}
	};

	template<typename T> using pimpl_ptr = unique_ptr<T>;
}


