///
/// \file       thread.h
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-04-15
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Some helpers for threads
///

#pragma once

#include <base/lock.h>
#include <base/thread.h>
#include <csl/util/assert.h>

namespace Csl
{
	using Genode::Lock;

	using Thread = Genode::Thread_deprecated<64UL * 1024 * sizeof( long )>;

	///
	/// Make a thread blockable with this mixin
	///
	class Blockable
	{
		private:
			Lock _lock;
		public:
			void block()
			{
				_lock.lock();
				_lock.lock();
				_lock.unlock();
			}

			template <typename FUNC>
			void block_and( FUNC const &f )
			{
				_lock.lock();
				f();
				_lock.lock();
				_lock.unlock();
			}


			void unblock()
			{
				_lock.unlock();
			}

			virtual ~Blockable() {}

			class Unblock_guard
			{
				private:
					Blockable &_blockable;
				public:
					Unblock_guard( Blockable &blockable ): _blockable( blockable ) {}
					~Unblock_guard()
					{
						_blockable.unblock();
					}

			};
	};

	template <typename TYPE>
	class Atomic_variable
	{
		private:
			TYPE _var;
			mutable Lock _lock;

			// can't copy
			Atomic_variable &operator=( const Atomic_variable &other );
			Atomic_variable( const Atomic_variable &other );
		public:
			template <typename ...ARGS>
			Atomic_variable( const ARGS &...args ): _var( args... ) {}

			const Atomic_variable &operator=( const TYPE &var )
			{
				Lock::Guard guard( _lock );
				_var = var;
				return *this;
			}

			const TYPE &get() const
			{
				Lock::Guard guard( _lock );
				return _var;
			}

			operator TYPE() const
			{
				return get();
			}
	};

	template <typename TYPE>
	struct Queue
	{
		public:
			using Type = TYPE;
		private:
			struct Item
			{
				Type val;
				Item *next;
				Item( const Type &val ): val( val ), next( nullptr ) {}
			};

			Item *_head;
			Item *_tail;
			size_t _count;
			mutable Lock _access;
		public:
			Queue(): _head( nullptr ), _tail( nullptr ), _count( 0 ) {}

			void enqueue( const Type val )
			{
				Lock::Guard guard( _access );
				Item *i = new Item( val );

				if ( 0 == _count )
				{
					_head = _tail = i;
				}
				else
				{
					_tail->next = i;
					_tail = i;
				}

				_count++;
			}

			size_t size() const
			{
				Lock::Guard guard( _access );
				return _count;
			}

			const Type dequeue()
			{
				Lock::Guard guard( _access );
				cslassert( 0 < _count );
				Type ret = _head->val;
				Item *oldhead = _head;
				_head = _head->next;
				delete oldhead;
				_count--;
				return ret;
			}

			~Queue()
			{
				Lock::Guard guard( _access );

				for ( Item *i = _head; nullptr != i; )
				{
					Item *old = i;
					i = i->next;
					delete old;
				}

			}
	};

	template <typename TYPE, size_t MAX = 10>
	class Blocking_queue
	{
		public:
			using Type = TYPE;
		private:
			Queue<Type> _queue;
			Lock _access;
			Blockable _consumer, _producer;
		public:
			const Type dequeue()
			{
				Lock::Guard guard( _access );

				if ( 0 == _queue.size() )
				{
					_consumer.block_and( [&]()
					{
						_access.unlock();
					} );
					// Allow the producer to add some data and for the lock again
					_access.lock();
				}

				_producer.unblock();
				return _queue.dequeue();
			}

			void enqueue( const Type &val )
			{
				Lock::Guard guard( _access );

				if ( _queue.size() == MAX )
				{
					_producer.block_and( [&]()
					{
						_access.unlock();
					} );
					_access.lock();
				}

				_queue.enqueue( val );
				_consumer.unblock();
			}
	};

	template <typename REPLY, typename MESSAGE>
	class Channel
	{
		private:
			Blocking_queue<MESSAGE,1> messages;
			Blocking_queue<REPLY,1> replies;
			Lock _access;
		public:
			const REPLY submit( const MESSAGE &message )
			{
				messages.enqueue( message );
				return replies.dequeue();
			}

			const MESSAGE get()
			{
				return messages.dequeue();
			}
			void put( const REPLY &reply )
			{
				replies.enqueue( reply );
			}

			template <typename FUNC>
			void proc( FUNC const &f )
			{
				put( f( get() ) );
			}
	};

} // namespace Csl

