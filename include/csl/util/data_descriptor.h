///
/// \file       data_descriptor.h
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \date       2015-12-04 14:53:22 +0100
///
/// \copyright  Copyright (C) 2015 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Generic data storage for pointer + length arithmetic.
///

#pragma once


#include <csl/util/util.h>
#include <csl/util/string.h>
#include <csl/util/logger.h>
#include <csl/util/assert.h>
#include <csl/util/stdint.h>

namespace Csl
{

	template <class T>
	class Data_descriptor_template
	{
		private:
			T _data;
			size_t  _size;

		public:
			typedef T type;

			/// Constructor.
			///
			/// \param T     pointer to data of type T.
			/// \param size  size of subject data.
			///
			Data_descriptor_template( T data, const size_t size )
				: _data( data ), _size( size )
			{
				cslassert( valid() );
			}

			/// Default Constructor.
			///
			/// Creates an invalid Data_descriptor.
			///
			Data_descriptor_template()
				: _data( nullptr ), _size( 0 ) {}

			/// \return private member.
			/// \pre instance must be valid.
			T data() const
			{
				cslassert( valid() );
				return _data;
			}

			/// \return private member.
			/// \pre instance must be valid.
			size_t size() const
			{
				cslassert( valid() );
				return _size;
			}

			/// Check if another Data_descriptor is "in" this Data_descriptor.
			///
			/// \param other   The other Data_descriptor.
			///
			/// \return        True iff the entire other Data_descriptor falls
			///                within this Data_descriptor.
			///
			bool in( const Data_descriptor_template &other ) const
			{
				return ( valid() ) &&
				       ( other.valid() ) &&
				       ( _data <= other.data() ) &&
				       ( ( other.data() + other.size() ) <= ( _data + _size ) );
			}

			/// Advance the Data_descriptor by s octects.
			///
			/// \verbatim
			///
			/// this:   [ <- _size         -> ]
			/// return: { <- s -> }[          ]
			///
			/// \endverbatim
			///
			/// \param s       Number of bytes to advance.
			///
			/// \return        Data_descriptor advanced (and shrunk) by s octets.
			///
			/// \pre instance must be valid.
			Data_descriptor_template advance( const size_t s ) const
			{
				cslassert( s <= _size );
				return Data_descriptor_template( _data + s, _size - s );
			}

			/// Subtract s octets from the Data_descriptor.
			///
			/// \verbatim
			///
			/// this:   [ <- _size         -> ]
			/// return: [        ]{ <- s   -> }
			///
			/// \endverbatim
			///
			/// \param s      Number of octets to subtract from the size.
			///
			/// \return       Data_descriptor with s octets subtracted.
			///
			/// \pre instance must be valid.
			Data_descriptor_template subtract( const size_t s ) const
			{
				cslassert( valid() );
				cslassert( s <= _size );
				return Data_descriptor_template( _data, _size - s );
			}

			/// Reduce the size of the Data_descriptor to s octets.
			///
			/// \verbatim
			///
			/// this:   [ <- _size         -> ]
			/// return: [ <- s   -> ]
			///
			/// \endverbatim
			///
			/// \param s      Size of the returned Data_descriptor.
			///
			/// \return       Data_descriptor reduced to s octets.
			///
			/// \pre instance must be valid.
			Data_descriptor_template reduce( const size_t s ) const
			{
				cslassert( valid() );
				cslassert( s <= _size );
				return Data_descriptor_template( _data, s );
			}

			/// Return a sub range of this Data_descriptor, s octets in size starting at offset
			///
			/// \verbatim
			///
			///	this:   [  [offset..]           ]
			/// return:              [ size  ]
			///
			/// \endverbatim
			///
			/// \param offset  Data_descriptor that delimits the start of the sub range.
			/// \param s       The number of octets spanned by the sub range.
			///
			/// \return        Data_descriptor starting at offset, s octets in size.
			///
			/// \pre instance and offset must be valid.
			Data_descriptor_template sub( const Data_descriptor_template &offset,
			                              const size_t s ) const
			{
				cslassert( in( offset ) );
				cslassert( _data <= offset.data()
				           && ( ( offset.data() + offset.size() + s ) <= ( _data + _size ) ) );
				return Data_descriptor_template( offset.data()+offset.size(), s );
			}

			/// Test if the other Data_descriptor is right adjecent to this Data_descriptor
			///
			/// \param other   The other Data_descriptor.
			///
			/// \return        True iff the other Data_descriptor is right adjecent to
			///                this Data_descriptor.
			///
			bool right_adjecent_to( const Data_descriptor_template &other ) const
			{
				return ( _data+size() == other.data() );
			}

			/// Returns a Data_descriptor that falls within this Data_descriptor
			///                and spans from the left to right + right.size
			///
			/// \verbatim
			///
			///	this:   [      [left..]   [right.......]    ]
			/// return:        [                       ]
			///
			/// \endverbatim
			///
			/// \param left    start of range (left.data())
			/// \param right   end of range (right.data() + right.size())
			///
			/// \pre instance, left and right must be valid.
			/// \pre left and right must be "in" instance.
			Data_descriptor_template sub_range( const Data_descriptor_template &left,
			                                    const Data_descriptor_template &right ) const
			{
				cslassert( in( left ) );
				cslassert( in( right ) );

				return Data_descriptor_template( left.data(),
				                                 ( right.data() - left.data() ) + right.size() );
			}

			/// Fit this Data_descriptor to include the inner Data_descriptor.
			///
			/// \verbatim
			///
			/// this:   [      [inner]    rest ]
			/// return: [            ]
			///
			/// \endverbatim
			///
			/// \param inner    Data_descriptor that delimits the new boundary.
			///
			/// \return         Data_descriptor that spans from the start of this
			///                 Data_descriptor to the end of the "inner" Data_descriptor.
			///
			/// \pre instance and inner must be valid.
			/// \pre inner must be "in" instance.
			Data_descriptor_template truncate( const Data_descriptor_template &inner ) const
			{
				cslassert( in( inner ) );
				return Data_descriptor_template( _data, inner.data() - _data + inner.size() );
			}

			/// Strip the "rest" Data_descriptor and all octets right of it.
			///
			/// \verbatim
			///
			/// this:   [      [rest   ]   ]
			/// return: [     ]
			///
			/// \endverbatim
			///
			/// \param rest     Data_descriptor that delimits the new boundary.
			///
			/// \return         Data_descriptor with the rest stripped off.
			///
			/// \pre instance and rest must be valid.
			/// \pre rest must be "in" instance.
			Data_descriptor_template strip( const Data_descriptor_template &rest ) const
			{
				cslassert( in( rest ) );
				return Data_descriptor_template( _data, rest.data() - _data );
			}

			/// Strip the "rest" Data_descriptor and all octets left of it.
			///
			/// \verbatim
			///
			/// this:   [      [rest   ]   ]
			/// return:                 [  ]
			///
			/// \endverbatim
			///
			/// \param rest     Data_descriptor that delimits the new boundary.
			///
			/// \return         Data_descriptor with the rest stripped off.
			///
			/// \pre instance and rest must be valid.
			/// \pre rest must be "in" instance.
			Data_descriptor_template tail( const Data_descriptor_template &rest ) const
			{
				cslassert( in( rest ) );
				Data_descriptor_template result( rest.data() + rest.size(),
				                                 _size - ( ( rest.data() - _data ) + rest.size() ) );
				cslassert( in( result ) );
				return result;
			}

			/// \return true if descriptor is valid, false otherwise.
			bool valid() const
			{
				return nullptr != _data;
			}

			/// Cast one Data_descriptor type to another
			///
			/// \param DD     Type to cast to.
			///
			/// \return       Casted Data_descriptor.
			///
			size_t end() const
			{
				return reinterpret_cast<size_t>( _data ) + _size;
			}


			template <class DD>
			DD to() const
			{
				return DD( ( typename DD::type ) _data, _size );
			}

			/// Convenience method to return a ustring with the data subject
			/// to the Data_descriptor.
			///
			/// \return ustring with a copy of the data subject to the Data_descriptor.
			operator ustring() const
			{
				return ustring( _data, _size );
			}

			/// Write zeroes to the memory subject to the Data_descriptor.
			///
			/// \return a copy of the Data_descriptor.
			///
			Data_descriptor_template nullify() const
			{
				cslassert( valid() );
				Genode::memset( _data, 0, _size );
				return *this;
			}

			/// Convenience method to return a hex_dump string of the data
			/// subject to the Data_descriptor.
			///
			/// \return a hex_dump string of the data subject to the Data_descriptor.
			Csl::string str() const
			{
				cslassert( valid() );
				return hex_string( _data, _size );
			}
	};

	/// Data_descriptor holds  pointer to const memory.
	typedef Data_descriptor_template<const uint8_t *> Data_descriptor;

	/// Data_descriptor holds  pointer to non-const memory.
	typedef Data_descriptor_template<      uint8_t *> Data_descriptor_mod;

	/// Data_descriptor holds const char*
	typedef Data_descriptor_template<const char *> Data_descriptor_c;

	/// Data_descriptor holds non-const char*
	typedef Data_descriptor_template<      char *> Data_descriptor_c_mod;

	/// Copy the data subject to the source Data_descriptor to the target
	/// Data_descriptor.
	///
	/// \param source    Data_descriptor to memory that should be copied.
	/// \param target    Data_descriptor to memory where should be copied to.
	///
	/// \pre source and target must be valid.
	/// \pre source must fit into target.
	///
	template<class T>
	void memcpy( const Data_descriptor_mod &target,
	             const Data_descriptor_template<T> &source )
	{
		cslassert( target.valid() );
		cslassert( source.valid() );
		cslassert( target.size() >= source.size() );
		Genode::memcpy( target.data(), source.data(), source.size() );
	}

	/// Compare the data subject to two Data_descriptors.
	///
	/// \param a   Data_descriptor that is compared to b.
	/// \param b   Data_descriptor that is compared to a.
	///
	/// \return 0  iff the data subject to a and b is equal.
	///
	template<class T>
	int memcmp( const Data_descriptor_template<T> &a,
	            const Data_descriptor_template<T> &b )
	{
		cslassert( a.valid() );
		cslassert( b.valid() );
		return Genode::memcmp( a.data(), b.data(), b.size() );
	}

	template<typename SERIALIZABLE>
	inline Csl::Data_descriptor to_data_descriptor( const SERIALIZABLE
	        &serializable )
	{
		return Csl::Data_descriptor( ( uint8_t * ) &serializable,
		                             sizeof( SERIALIZABLE ) );
	}



}

/// Stream operator overload to serialize a serializable class.
///
/// \param d            Memory to serialize to.
/// \param serializable An instance of a serializable class.
///
/// \return a writable Data_descriptor that represents the rest of d after
/// serialization.
///
template <class S>
inline Csl::Data_descriptor_mod operator<<( Csl::Data_descriptor_mod d,
        const S &serializable )
{
	return serializable.serialize( d );
}

/// Stream operator overload to serialize a string.
///
/// \param d  Memory to serialize to.
/// \param s  String to serialize.
///
/// \return a writable Data_descriptor that represents the rest of d after
/// serialization.
///
template<>
inline Csl::Data_descriptor_mod operator<<( Csl::Data_descriptor_mod d,
        const Csl::string &s )
{
	cslassert( d.size() > s.size() );
	Genode::memcpy( d.data(), s.data(), s.size() );
	return d.advance( s.size() );
}

/// Stream operator overload to serialize the data represented by a Data_descriptor.
///
/// \param dst  Memory to serialize to.
/// \param src  Data_descriptor that represents the data that should be serialized.
///
/// \return a writable Data_descriptor that represents the rest of dst after
/// serialization.
///
// XXX TODO check if this function could be removed considering the similar function
// with double template arguments below
template<class T>
inline Csl::Data_descriptor_mod operator<<( Csl::Data_descriptor_mod dst,
        Csl::Data_descriptor_template<T> src )
{
	cslassert( dst.size() >= src.size() );
	Genode::memcpy( dst.data(), src.data(), src.size() );
	return dst.advance( src.size() );
}

/// Stream operator overload to serialize the data represented by a Data_descriptor.
///
/// \param dst  Memory to serialize to.
/// \param src  Data_descriptor that represents the data that should be serialized.
///
/// \return a writable Data_descriptor that represents the rest of dst after
/// serialization.
///
template<class T, class TMOD>
inline Csl::Data_descriptor_template<TMOD> operator<<
( Csl::Data_descriptor_template<TMOD> dst,
  Csl::Data_descriptor_template<T> src )
{
	cslassert( dst.size() >= src.size() );
	Genode::memcpy( dst.data(), src.data(), src.size() );
	return dst.advance( src.size() );
}

/// Convencience method to print a long string in multiple stages.
inline void staged_print( ustring s )
{
	static constexpr const size_t STAGE = 512;

	for ( size_t i = 0; i < s.size(); i += STAGE )
	{
		auto sub = s.substr( i, STAGE );
		TLOG( "%s", hex_string( sub ).c_str() );
	}
}

