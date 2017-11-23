///
/// \file       list.h
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \date       2015-04-21 04:45:16 -0700
///
/// \copyright  Copyright (C) 2014 - 2015 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief
///

#pragma once

#include <csl/util/exception.h>

namespace Csl
{
	template<typename T>
	class List
	{
		private:
			class Element;
		public:


			class Iterator
			{
				public:
					Element *_i;
					// COMMENT: no checks id _i is a nullptr.

					Iterator( Element *i )
						: _i( i ) {}

					const bool      is_last()                      const
					{
						return _i->next() == nullptr;
					}
					const Iterator  next()                         const
					{
						return Iterator( _i->next() );
					}
					const Iterator  prev()                         const
					{
						return Iterator( _i->prev() );
					}
					const bool      equals( const Iterator i )       const
					{
						return ( i._i == _i );
					}
					const T         get()                          const
					{
						return _i->get();
					}
					// operators:
					const bool      operator== ( const Iterator r )  const
					{
						return equals( r );
					}
					const bool      operator!= ( const Iterator r )  const
					{
						return !equals( r );
					}
					const T         operator* ()                  const
					{
						return _i->get();
					}
					T *operator->()
					{
						return &_i->_t;
					}
					const T *operator->() const
					{
						return &_i->_t;
					}

					const Iterator &operator++ ()
					{
						_i = _i->next();
						return *this;
					}

					const Iterator &operator++( int )
					{
						auto tmp = *this;
						_i = _i->next();
						return tmp;
					}
			};

			typedef Iterator iterator;
			typedef Iterator const_iterator;

		private:

			class Element
			{

				private:
					T _t;
					Element *_prev = nullptr;
					Element *_next = nullptr;

				public:
					Element( T t )
						: _t( t ) {}

					~Element() {}

					const T  get()           const
					{
						return _t;
					}
					T  get()
					{
						return _t;
					}
					Element *const next()    const
					{
						return _next;
					}
					Element *const prev()    const
					{
						return _prev;
					}
					void next( Element *const e )
					{
						_next = e;
					}
					void prev( Element *const e )
					{
						_prev = e;
					}
					friend class Iterator;
			};


			Element *_head = nullptr;
			Element *_tail = nullptr;
			size_t   _size = 0;

		public:

			// default constructor
			List() {}

			// copy constructor; makes a deep copy
			List( const List<T> &other )
			{
				for ( T t : other )
				{
					push_back( t );
				}
			}

			virtual ~List()
			{
				clear();
			}

			void clear()
			{
				while ( _head != nullptr )
				{
					erase( Iterator( _head ) );
				}
			}

			// TODO make test case for assignment operator
			List<T> operator= ( const List<T> &other )
			{
				if ( this != &other )
				{
					// destroy all elements in the list
					while ( _head != nullptr )
					{
						erase( Iterator( _head ) );
					}

					for ( T t : other )
					{
						push_back( t );
					}
				}

				return *this;
			}

			void push_back( T t )
			{
				//			FLOG("push_back called" );
				Element *e = new Element( t );

				//			FLOG(" new element created");
				if ( _head == nullptr )
				{
					_head = e;
				}

				if ( _tail != nullptr )
				{
					_tail->next( e );
				}

				e->prev( _tail );
				_tail = e;
				_size++;
			}

			T        front() const
			{
				if ( _head == nullptr )
				{
					throw Empty();
				}

				return _head->get();
			}
			T        back() const
			{
				if ( _tail == nullptr )
				{
					throw Empty();
				}

				return _tail->get();
			}
			size_t   size()  const
			{
				return _size;
			}
			bool     empty() const
			{
				return _size==0;
			}
			Iterator begin() const
			{
				return Iterator( _head );
			}
			//Iterator end()   const {return Iterator(_tail);}
			Iterator end()   const
			{
				return Iterator( nullptr );
			}

			void erase( Iterator i )
			{
				// assert that Iterator points to valid element
				if ( i._i == nullptr )
				{ throw Out_of_range(); }

				// re-tie next and prev pointers of element
				if ( i._i->next() != nullptr )
				{
					i._i->next()->prev( i._i->prev() );
				}

				if ( i._i->prev() != nullptr )
				{
					i._i->prev()->next( i._i->next() );
				}

				// if head element is erased, set new head
				if ( i._i == _head )
				{
					_head = _head->next();
				}

				// if tail element is erased, set new tail
				if ( i._i == _tail )
				{
					_tail = _tail->prev();
				}

				delete i._i;
				_size--;
			}

			const T at( const size_t pos ) const
			{
				if ( _size <= pos )
				{ throw Out_of_range(); }

				Iterator it = begin();

				for ( size_t i = 0; i<pos; i++ )
				{
					it = it.next();
				}

				return it.get();;
			}
	};


	//Inefficient way to replace stl. replace this later with a
	//binary tree

	template <typename T>
	class List_set: public List<T>
	{
		public:
			//using ::List<T>::List;
			using Iterator = typename List<T>::Iterator;

			const Iterator find( const T &item ) const
			{
				for ( Iterator i = List<T>::begin(); i != List<T>::end(); ++i )
					if ( *i == item )
					{
						return i;
					}

				return List<T>::end();
			}

			bool exists( const T &item ) const
			{
				return List<T>::end() != find( item );
			}

			bool operator==( const List_set &other ) const
			{
				if ( List<T>::size() != other.size() )
				{
					return false;
				}

				for ( auto i : *this )
				{
					if ( not other.exists( i ) )
					{
						return false;
					}
				}

				return true;
			}

			bool operator!=( const List_set &other ) const
			{
				return not( *this == other );
			}

			void insert( const T &item )
			{
				List<T>::push_back( item );
			}
	};

	template <typename T>
	using Set = List_set<T>; // Replace with binary tree based set
}

