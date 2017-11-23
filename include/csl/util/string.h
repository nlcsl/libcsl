///
/// \file       string.h
/// \author     Menno Valkema <valkema@nlcsl.com>
/// \date       2015-04-21 04:45:16 -0700
///
/// \copyright  Copyright (C) 2014 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief Implementation of subset of std::string functionality to replace STL.
///

#pragma once

#include <util/string.h>
#include <stdarg.h>
#include <base/printf.h>
#include <base/log.h>

#include <csl/util/stdint.h>
#include <csl/util/hash.h>
#include <csl/util/algorithm.h>
#include <csl/util/exception.h>

namespace Csl
{

	template <typename CHAR>
	size_t strlen( const CHAR *begin )
	{
		size_t i = 0;

		while ( begin[i] != CHAR( 0 ) )
		{
			++i ;
		}

		return i;
	}

	template <typename CHAR>
	int strcmp( const CHAR *const str1, const CHAR *const str2, const size_t len )
	{
		for ( size_t i = 0 ; i < len; ++i )
		{
			if ( str1[i] != str2[i] )
			{
				return str1[i] - str2[i];
			}
		}

		return 0;
	}

	template <typename CHAR>
	class Basic_string
	{
		public:
			using size_t = Csl::size_t;
			using Type = CHAR;

			static const size_t npos = ~0;
		private:
			class Storage
			{
				private:
					size_t _capacity;
					Type *_data;
				public:
					Storage( const size_t capacity = 1 ):
						_capacity( 1 ), _data( nullptr )
					{
						guarantee( capacity );
						nullify();
					}

					void nullify()
					{
						Genode::memset( _data, 0, _capacity * sizeof( Type ) );
					}

					void guarantee( size_t capacity = 4 )
					{
						capacity++;

						if ( _capacity >= capacity )
						{
							return;
						}

						size_t new_capacity = _capacity;

						while ( new_capacity < capacity )
						{
							new_capacity *= 2;
						}

						Type *new_data = new Type[new_capacity];

						if ( nullptr != _data )
						{
							Genode::memset( new_data, 0, new_capacity * sizeof( Type ) );
							Genode::memcpy( new_data, _data, _capacity * sizeof( Type ) );
							delete[] _data;
						}

						_capacity = new_capacity;
						_data = new_data;
					}

					Type *data()
					{
						return _data;
					}
					const Type *const data() const
					{
						return _data;
					}
					const size_t capacity() const
					{
						return _capacity;
					}

					const Storage &operator=( const Storage &other )
					{
						if ( this == &other )
						{
							return *this;
						}

						nullify();
						guarantee( other.capacity() );
						Genode::memcpy( _data, other._data, sizeof( Type ) * other.capacity() );
						return *this;
					}

					Storage( const Storage &other ): Storage( other._capacity )
					{
						*this = other;
					}
					Storage( const Storage
					         &&other ): _capacity( other._capacity ), _data( other._data ) {}
					~Storage()
					{
						nullify();
						delete[] _data;
					}
			};

			class Char_set
			{
				private:
					const Type *_begin;

				public:
					Char_set( const Type *set ): _begin( set ) {}

					bool has_member( const Type c ) const
					{
						for ( size_t i = 0; i < strlen<Type>( _begin ); ++i )
						{
							if ( _begin[i] == c )
							{
								return true;
							}
						}

						return false;
					}
			};

			Storage _storage;
			size_t _length;
		public:

			class Iterator
			{
					Type *_start;
					size_t _offset;

					const Type *_get() const
					{
						return _start + _offset;
					}
					Type *_get()
					{
						return _start + _offset;
					}
				public:
					Iterator( Type *start, size_t offset = 0 ): _start( start ),
						_offset( offset ) {}

					const Iterator &operator=( const Iterator &iterator )
					{
						if ( this == &iterator )
						{
							return *this;
						}

						_offset = iterator._offset;
						_start = iterator._start;
						return *this;
					}

					bool operator==( const Iterator &iterator ) const
					{
						return _get() == iterator._get();
					}
					bool operator==( const size_t &offset ) const
					{
						return offset == _offset;
					}
					bool operator!=( const Iterator &iterator ) const
					{
						return _get() != iterator._get();
					}
					bool operator>( const Iterator &iterator ) const
					{
						return _get() > iterator._get();
					}
					bool operator>=( const Iterator &iterator ) const
					{
						return _get() >= iterator._get();
					}
					bool operator<( const Iterator &iterator ) const
					{
						return _get() < iterator._get();
					}
					bool operator<=( const Iterator &iterator ) const
					{
						return _get() <= iterator._get();
					}

					Type &operator*()
					{
						return *_get();
					}
					Type *operator->()
					{
						return _get();
					}
					const Type &operator*() const
					{
						return *_get();
					}
					const Type *operator->() const
					{
						return _get();
					}

					Iterator operator++()
					{
						return Iterator( _start, ++_offset );
					}
					Iterator operator--()
					{
						return Iterator( _start,  --_offset );
					}
					Iterator operator++( int )
					{
						return Iterator( _start, _offset++ );
					}
					Iterator operator--( int )
					{
						return Iterator( _start, _offset++ );
					}
			};

			Iterator begin()
			{
				return Iterator( _storage.data(),0 );
			}
			Iterator end()
			{
				return Iterator( _storage.data(), _length );
			}
			const Iterator begin() const
			{
				return Iterator( ( Type * )_storage.data() );
			}
			const Iterator end() const
			{
				return Iterator( ( Type * )_storage.data(),  _length );
			}

			Basic_string(): _storage(), _length( 0 ) {};

			Basic_string( const Basic_string &other ):
				_storage( other._storage ),
				_length( other._length ) {}

			Basic_string( const Type *begin, size_t size )
			{
				_storage.guarantee( size );
				_length = size;
				Genode::memcpy( _storage.data(), begin, sizeof( Type ) * size );
			}

			Basic_string( const Type *begin ): Basic_string( begin,
				        strlen<Type>( begin ) ) {}

			Basic_string( const size_t s, const  Type c ): _storage( s ), _length( s )
			{
				for ( size_t i = 0; i < _length; ++i )
				{
					_storage.data()[i] = c;
				}
			}

			size_t size() const
			{
				return _length;
			}
			bool empty() const
			{
				return 0 == _length;
			}
			size_t length() const
			{
				return _length;
			}
			const Type *data() const
			{
				return _storage.data();
			}
			const Type *c_str() const
			{
				return _storage.data();
			}

			size_t find_last_not_of( const Type *c ) const
			{
				Char_set set( c );

				for ( size_t i = size() - 1; i >= 0; --i )
				{
					if ( not set.has_member( data()[i] ) )
					{
						return i;
					}
				}

				return npos;
			}

			void erase( size_t len )
			{
				_length = len;
			}

			const Basic_string substr( size_t pos = 0, size_t len = npos ) const
			{

				if ( npos ==  len )
				{
					len = size() - pos;
				}

				if ( pos + len > size() )
				{
					len = size() - pos;
				}

				return Basic_string( _storage.data() + pos, len );
			}

			const Type operator[]( const size_t index ) const
			{
				return at( index );
			}

			const Basic_string operator+( const Basic_string &other ) const
			{
				Basic_string res( *this );
				res += other;
				return res;
			}

			bool operator==( const Basic_string &r ) const
			{
				return  compare( r ) == 0;
			}
			bool operator!=( const Basic_string &r ) const
			{
				return  compare( r ) != 0;
			}
			bool operator<( const Basic_string &r ) const
			{
				return  compare( r ) < 0;
			}
			bool operator>( const Basic_string &r ) const
			{
				return  compare( r ) > 0;
			}
			bool operator<=( const Basic_string &r ) const
			{
				return  compare( r ) <= 0;
			}
			bool operator>=( const Basic_string &r ) const
			{
				return  compare( r ) >= 0;
			}

			Basic_string &operator+=( const Basic_string &other )
			{
				_storage.guarantee( _length + other._length );
				Genode::memcpy( &_storage.data()[_length], other.data(), other.size() );
				_length += other._length;
				return *this;
			}

			int compare( const Basic_string &other ) const
			{
				const size_t max = min( size(), other.size() );
				const int res = Csl::strcmp<Type>( data(), other.data(), max );

				if ( 0 == res )
				{
					// TODO this goes wrong if the strings are equal but have different capacity
					return size() - other.size();
				}

				return res;
			}

			bool contains_at( const Basic_string &pattern, size_t offset ) const
			{
				if ( pattern.size() > size() - offset )
				{
					return false;
				}
				else
				{
					return Csl::strcmp<Type>( data() + offset, pattern.data(),
					                          pattern.size() ) == 0;
				}
			}

			const Type at( size_t index ) const
			{
				if ( index >= size() )
				{
					throw Out_of_range();
				}

				return data()[index];
			}

			size_t find( const Type &c, size_t pos = 0 ) const
			{
				for ( ; pos < size(); ++pos )
				{
					if ( c == at( pos ) )
					{
						return pos;
					}
				}

				return npos;
			}

			size_t find( const Basic_string &pattern, size_t pos = 0 ) const
			{
				size_t diff = (size() < pattern.size()) ? 0 : size() - pattern.size();

				for ( ; pos <= diff; ++pos )
				{
					if ( ! Csl::strcmp<Type>( data() + pos, pattern.data(), pattern.size() ) )
					{
						return pos;
					}
				}

				return npos;
			}

			void reserve( size_t n = 0 )
			{
				_storage.guarantee( n );
			}

			void push_back( const Type &c )
			{
				_storage.guarantee( size() + 1 );
				_storage.data()[ size() ] = c;
				_length++;
			}

			Basic_string &append( const Basic_string &s )
			{
				*this += s;
				return *this;
			}


			Basic_string &append( const Type *c, size_t len )
			{
				Basic_string appendix( c, len );
				*this += appendix;
				return *this;
			}
	};

	using  string = Basic_string<char>;
	using  ustring = Basic_string<uint8_t>;

	const Csl::string sprintf( const Csl::string &fmt, ... );
	const Csl::string vsprintf( const Csl::string &fmt, va_list args );
	const void printf( const Csl::string &fmt, ... );

	using Genode::strcmp;

	template<typename T>
	struct hash<Csl::Basic_string<T>>
	{
		using String_type = Csl::Basic_string<T>;
		size_t operator()( const String_type &data )
		{
			return djb2hash( ( uint8_t * ) data.data(), data.size() * sizeof( T ) );
		}
	};

}

template <typename T>
const Csl::Basic_string<T> operator+( const Csl::Basic_string<T> l,
                                      const Csl::Basic_string<T> &r )
{
	Csl::Basic_string<T> res;
	res.append( l );
	res.append( r );
	return res;
}

template <typename T>
const Csl::Basic_string<T> operator+( const T *l,
                                      const Csl::Basic_string<T> &r )
{
	Csl::Basic_string<T> res( l );
	res.append( r );
	return res;
}

using ustring = Csl::Basic_string<Csl::uint8_t>;


static char _upcase( const char c )
{
	if ( 'a' <= c && c <= 'z' )
	{
		return c - ( 'a' - 'A' );
	}

	return c;
}

inline ustring hex_to_ustring( const Csl::string hex )
{
	static const Csl::string HEX_DIGITS( "0123456789ABCDEF" );

	if ( hex.size() % 2 )
	{
		return ustring();
	}

	ustring res;

	for ( Csl::size_t i = 0; i < hex.size(); ++i )
	{
		const Csl::uint8_t hc = HEX_DIGITS.find( _upcase( hex[i] ) );
		++i;
		const Csl::uint8_t lc = HEX_DIGITS.find( _upcase( hex[i] ) );

		if ( hc == ustring::npos )
		{
			return ustring();
		}

		if ( lc == ustring::npos )
		{
			return ustring();
		}

		Csl::uint8_t r = ( 0xff & hc ) << 4 | ( 0xff & lc );
		res.push_back( r );
	}

	return res;
}

