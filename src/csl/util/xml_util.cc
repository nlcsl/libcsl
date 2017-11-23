///
/// \file       csl/util/xml_util.cc
///	\author     Boris Mulder <boris.mulder@nlcsl.com>
/// \date       17-03-2017
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///

#include <csl/util/xml_util.h>

namespace Csl
{

	const Xml_path::Special_char Xml_path::NODE_SEPARATOR
	{
		'/', "slash"
	};
	const Xml_path::Special_char Xml_path::ATTR_SEPARATOR
	{
		':', "colon"
	};
	const Xml_path::Special_char Xml_path::VALUE_SEPARATOR
	{
		'=', "equals"
	};
	const Xml_path::Special_char Xml_path::ESCAPE
	{
		'&', "amp"
	};
	const Xml_path::Special_char Xml_path::INVALID
	{
		'\0', "invalid"
	};

	const Xml_path::Special_char Xml_path::special_char_list[] =
	{
		NODE_SEPARATOR,
		ATTR_SEPARATOR,
		VALUE_SEPARATOR,
		ESCAPE,
		INVALID
	};

	string xml_escape( string src )
	{
		string res;

		for ( char c : src )
		{
			switch ( c )
			{
			case 0:
				res.append( "&#x00;" );
				break;

			case '>':
				res.append( "&gt;" );
				break;

			case '<':
				res.append( "&lt;" );
				break;

			case '&':
				res.append( "&amp;" );
				break;

			case '"':
				res.append( "&quot;" );
				break;

			case '\'':
				res.append( "&apos;" );
				break;

			default:
				res.push_back( c );
				break;
			}
		}

		return res;
	}

	string get_node_val( const Genode::Xml_node &node )
	{
		Csl::Byte_array<256> res;

		node.value( res.val, res.capacity() );

		return res.str();
	}

	/*
	 * just like Xml_node::attribute_value, but with exception instead of default, and 256 max length
	 */
	string get_attribute_val( const Genode::Xml_node &node, const string attribute )
	{
		Csl::Byte_array<256> res;

		try
		{
			node.attribute( attribute.c_str() ).value( res.val, res.capacity() );
		}
		catch ( Genode::Xml_attribute::Nonexistent_attribute )
		{
			fthrow<Nonexistent_attribute>( "attribute %s not found in node %s",
			                               attribute.c_str(), node.type().string() );
		}

		return res.str();
	}
}
