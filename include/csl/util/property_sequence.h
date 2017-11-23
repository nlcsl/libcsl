///
/// \file       property_sequence.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-01-05
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      In memory data structure to to communicate a sequence of settings via shared memory
///

#pragma once

#include <csl/util/data_descriptor.h>
#include <csl/util/exception.h>
#include <csl/util/string.h>
#include <csl/util/stdint.h>
#include <csl/util/logger.h>

namespace Csl
{
	///
	/// Datastructure to communicate settings via shared
	/// memory. Properties stored have a type and a variable
	/// length. Hence each item has a type, a length, and length
	/// bytes of data. Each property can be stored only once.
	///
	/// Due to the organisation of the data structure get and set
	/// methods are NOT O( 1 ) but O( N ) where N is number of
	/// bytes stored in the data structure.
	///
	/// This data structure should be used for _occasional_
	/// communication of variable length settings. When used
	/// frequently (say for every packet received), this data
	/// structure might be a performance bottleneck.
	///
	class Property_sequence
	{
		public:
			struct iterator;
			struct item;
			using Property = uint8_t;
			static const Property LAST = 0;
		private:
			Data_descriptor_mod _mem; /// Memory range
			item *_begin;  /// First item in the data structure.

			/// Internal method to get a property
			///
			/// \param p the property to get
			///
			/// \return the item represented by p, if p is
			///         not stored, nullptr is returned.
			///
			item *_get( const Property &p ) const
			{
				cslassert( p != LAST );

				for ( iterator i = begin(); i != end(); ++i )
				{
					const size_t item_end = ( size_t )i.value + i.value->size;
					cslassert( _mem.end() >= item_end );

					if ( p == i.value->type )
					{
						return i.value;
					}
				}

				DLOG( "not found: %i", p );
				fthrow<Exception>( "Property not found" );
				return nullptr;
			}

			/// Set property p. User of this class is
			/// expected not to set the same property
			/// twice.
			///
			/// \param p type of the proprty
			/// \param size length of the data
			/// \param data the data.
			///
			void _set( const Property &p, const size_t size,  const void *data )
			{
				cslassert( p != 0 );

				iterator i;

				for ( i = begin(); i != end(); ++i )
				{
					cslassert( p != i.value->type );
				}

				item *const last = i.value;
				const size_t item_end = reinterpret_cast<size_t>( last ) + sizeof(
				                            *last ) + size;

				if ( _mem.end() < item_end )
				{
					fthrow<Exception>( "Not enough space for data." );
				}

				last->type = p;
				last->size = size;
				Genode::memset( last->data, 0, last->size );
				Genode::memcpy( last->data, const_cast<void *>( data ), size );
				auto tail = last->next();
				const size_t tail_end = reinterpret_cast<size_t>( tail ) + sizeof( *tail );

				if ( _mem.end() < tail_end )
				{
					fthrow<Exception>( "Not enough space for tail" );
				}

				tail->type = LAST;
				tail->size = 0;
			}

		public:
			/// Item used to store variable length data.
			///
			struct item
			{
				Property type;
				size_t size;
				uint8_t data[];

				///
				/// Returns a pointer to the next item
				/// in a sequence, calculated based on the
				/// size of data[]
				///
				/// \return the next item in the sequence.
				///
				item *next()
				{
					return reinterpret_cast<item *>( ( uint8_t * )this  + sizeof( *this ) + size );
				}
			};

			///
			/// Iterator to iterate forward over a
			/// settings sequence.
			///
			struct iterator
			{
				item *value;
				bool operator!=( const iterator &r )
				{
					if ( value->type == LAST && r.value->type == LAST )
					{
						return false;
					}

					return value != r.value;
				}


				item &operator*()
				{
					return *value;
				}

				iterator &operator++()
				{
					value = value->next();
					return *this;
				}
				iterator operator++( int )
				{
					iterator tmp( *this );
					operator++();
					return tmp;
				}
			};

			/// Constructor to create a sequence. Memory
			/// will be initialized, and it is assumed no
			/// data is stored in mem.
			///
			/// \param mem memory to be initialized
			///
			explicit Property_sequence( const Data_descriptor_mod &mem ):
				_mem( mem ), _begin( reinterpret_cast<item *>( mem.data() ) )
			{
				reset();
			}

			void reset()
			{
				_mem.nullify();
				*_begin = { LAST, 0 };
			}

			/// Constructor to use a previously initialized sequence.
			///
			/// \param mem descriptor to an existing configuration sequenc..
			///
			explicit Property_sequence( const Data_descriptor &mem ): _mem(
				    mem.to<Data_descriptor_mod>() ),
				_begin( reinterpret_cast<item *>( const_cast<uint8_t *>( mem.data() ) ) )
			{
			}

			explicit Property_sequence() {}

			///  Iterator pointing at the first item.
			///
			///
			/// \return iterator to first item.
			///
			iterator begin()
			{
				return iterator { _begin };
			}
			const iterator begin() const
			{
				return iterator { _begin };
			}


			/// Iterator to end of the structure.
			///
			///
			/// \return
			///
			const iterator end() const
			{
				static const item L
				{
					LAST, 0
				};
				return iterator {const_cast<item *>( &L )};
			}

			/// Get a property.
			///
			/// \param t the property to get.
			///
			template <Property P, typename T>
			void get( T &t ) const
			{
				item *i = _get( P );
				t = *( ( T * ) i->data );
			}

			template<Property P>
			void get( Csl::string &s ) const
			{
				item *i = _get( P );
				s = Csl::string( reinterpret_cast<char *>( i->data ), i->size );
			}

			template<Property P>
			void get( ustring &s ) const
			{
				item *i = _get( P );
				s = ustring( reinterpret_cast<uint8_t *>( i->data ), i->size );
			}


			template<Property P>
			void get( Data_descriptor_mod &s ) const
			{
				item *i = _get( P );
				s = Data_descriptor_mod( i->data, i->size ) ;
			}

			/// Set a property
			///
			/// \param value value to set.
			///
			template <Property P, typename T>
			void set( const T &value )
			{
				_set( P, sizeof( T ), &value );
			}

			template <Property P>
			void set( const Csl::string &s )
			{
				_set( P, s.size(), s.data() );
			}

			template <Property P>
			void set( const Csl::ustring &s )
			{
				_set( P, s.size(), s.data() );
			}

			template <Property P>
			void set( const Csl::Data_descriptor &d )
			{
				_set( P, d.size(), d.data() );
			}
	};
}

