///
/// \file       xml_util.h
/// \author     Boris Mulder <boris.mulder@nlcsl.com>
/// \date       21-02-2017
///
/// \copyright  Copyright (C) 2017 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief		Tools for retrieving and setting xml nodes based on a "path" string
///
///	\syntax
///		path = node[/node]*
///		node = tagname[:attribute=value]*
///
///		special characters ('/', ':', '=', '&') are escaped as follows, resp.:
///		&slash, &colon, &equals, &amp
///
/// \example
///  "csl/node1:name=foo:url=www.nu.nl&slashbla/node2:value=bar:n=1"
///
///	 this corresponds to the 'node2' node with value 'bar' and n '1' in the following xml:
///	 <csl>
///	 	<node1 name="foo" url="www.nu.nl/bla">
///	 		<node2 value="bar" n="1"/>
///			<node2 value="bar" n="2"/>
///	 	</node1>
///	 </csl>
///

#pragma once

#include <csl/util/string_util.h>
#include <csl/util/list.h>
#include <csl/util/fthrow.h>
#include <csl/util/byte_array.h>

#include <util/xml_generator.h>
#include <util/xml_node.h>
#include <util/misc_math.h>

namespace Csl
{

	EXCEPTION( No_matching_attribute );
	EXCEPTION( Invalid_syntax );
	EXCEPTION( Nonexistent_sub_node );
	EXCEPTION( Nonexistent_attribute );

	string xml_escape( string src );
	string get_node_val( const Genode::Xml_node &node );
	string get_attribute_val( const Genode::Xml_node &node,
	                          const string attribute );


	class Xml_path
	{
		public:
			using Xml_node = Genode::Xml_node;
			using Xml_generator = Genode::Xml_generator;

			struct Special_char
			{
				char c;
				const char *escape_sequence;

				Special_char( char ch ) : c( ch ), escape_sequence() {}
				Special_char( char ch , const char *seq ) : c( ch ), escape_sequence( seq ) {}
			};

			static const Special_char NODE_SEPARATOR;
			static const Special_char ATTR_SEPARATOR;
			static const Special_char VALUE_SEPARATOR;
			static const Special_char ESCAPE;
			static const Special_char INVALID;

			static const Special_char special_char_list[5];


			static string unescape( const string &s )
			{
				string result;

				for ( size_t i = 0; i < s.size(); i++ )
				{
					if ( s.at( i ) == ESCAPE.c )
					{
						for ( Special_char sp : special_char_list )
						{
							if ( sp.c == '\0' )
							{
								throw Invalid_syntax( "Invalid escape sequence" );
							}

							if ( s.contains_at( string( sp.escape_sequence ), i + 1 ) )
							{
								result.push_back( sp.c );
								i += Genode::strlen( sp.escape_sequence );
								break;
							}
						}
					}
					else
					{
						result.push_back( s.at( i ) );
					}
				}

				return result;
			}

		private:
			struct Attribute
			{
				string name;
				string value;

				Attribute( string n, string v ) : name( n ), value( v ) {}

				string str()
				{
					return sprintf( "%s: %s", name.c_str(), value.c_str() );
				}
			};

			string _path;

			Attribute _parse_attr( const string &attr_str ) const
			{
				auto l = split( attr_str, VALUE_SEPARATOR.c );

				if ( l.size() != 2 )
				{
					fthrow<Invalid_syntax>( "Syntax error in xml path in attribute %s: expected 'name=value'",
					                        attr_str.c_str() );
				}

				string name = unescape( l.front() );
				string value = unescape( l.back() );

				return Attribute( name, value );
			}

			bool _has_attributes( const Xml_node &node,
			                      const List<string> &attributes ) const
			{
				bool result = true;

				for ( string attr_str : attributes )
				{
					Attribute attr = _parse_attr( attr_str );
					string value = get_attribute_val( node, attr.name );

					// AND the comparison with result
					result &= ( value == attr.value );
				}

				return result;
			}

			Xml_node _parse_node( const Xml_node &node, const string &node_str ) const
			{
				// pop name of the node from the list
				auto attributes = split( node_str, ATTR_SEPARATOR.c, false );
				string nodename = unescape( attributes.front() );
				attributes.erase( attributes.begin() );

				try
				{
					Xml_node subnode = node.sub_node( nodename.c_str() );

					// match the attributes
					if ( !attributes.empty() )
					{
						bool success = false;
						node.for_each_sub_node( nodename.c_str(), [&]( const Genode::Xml_node &n )
						{
							if ( _has_attributes( n, attributes ) )
							{
								subnode = n;
								success = true;
							}
						} );

						if ( !success )
							fthrow<No_matching_attribute>( "No matching subnode found for node %s with attributes '%s'",
							                               nodename.c_str(), node_str.c_str() );
					}

					return subnode;
				}
				catch ( Genode::Xml_node::Nonexistent_sub_node )
				{
					fthrow<Nonexistent_sub_node>( "No subnode '%s' in node %s. xml: %s",
					                              nodename.c_str(), node.type().string(), node.addr() );
					// keep compiler happy
					throw Nonexistent_sub_node();
				}
			}

			void _create_subnode( Xml_generator &xml, List<string> &nodes )
			{
				// stop if empty
				if ( nodes.size() == 0 )
				{
					return;
				}

				//get first node
				string node_str = nodes.front();

				// pop name of the node from the list
				auto attributes = split( node_str, ATTR_SEPARATOR.c, false );
				string nodename = xml_escape( unescape( attributes.front() ) );

				// remove name so attributes remain
				attributes.erase( attributes.begin() );

				// remove head from list
				nodes.erase( nodes.begin() );

				// add attributes
				xml.node( nodename.c_str(), [&]()
				{
					for ( string attr_str : attributes )
					{
						Attribute a = _parse_attr( attr_str );
						xml.attribute( xml_escape( a.name ).c_str(), xml_escape( a.value ).c_str() );
					}

					_create_subnode( xml, nodes );
				} );
			}

		public:
			Xml_path( const string path ) : _path( path ) {}

			/*
			 * find_node finds a subnode based on a 'path' from the root
			 *
			 * \param node: the root node
			 * \throws: Nonexistent_attribute, Nonexistent_sub_node, No_matching_attribute, Invalid_syntax
			 */
			Xml_node get_node( const Xml_node &node ) const
			{
				Xml_node curr = node;

				for ( string node_str : split( _path, NODE_SEPARATOR.c, false ) )
				{
					// step down into the right subnode
					curr = _parse_node( curr, node_str );
				}

				return curr;
			}

			const string &str() {
				return _path;
			}

			/*
			 * create a node tree based on the path
			 *
			 * \param dst: the buffer to write the xml to
			 * \param len: the maximum length
			 * \return: the number of characters written
			 */
			size_t create_node( char *dst, size_t len ) const
			{
				auto nodes = split( _path, NODE_SEPARATOR.c, false );
				string root = nodes.front();
				auto root_attributes = split( root, ATTR_SEPARATOR.c, false );
				string rootname = xml_escape( unescape( root_attributes.front() ) );

				// remove name from attrs
				root_attributes.erase( root_attributes.begin() );
				// remove root from nodes
				nodes.erase( nodes.begin() );

				Genode::Xml_generator xml( dst, len, rootname.c_str(), [&]()
				{
					for ( string attr_str : root_attributes )
					{
						// set root attributes
						Attribute a = _parse_attr( attr_str );
						xml.attribute( xml_escape( a.name ).c_str(), xml_escape( a.value ).c_str() );
					}

					_create_subnode( xml, nodes );
				} );

				return xml.used();
			}

			Xml_path append( const string &appendix ) const
			{
				string res = _path + appendix;
				return Xml_path( res.c_str() );
			}
	};
}
