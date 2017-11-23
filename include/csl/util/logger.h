///
/// \file       logger.h
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \date       2015-07-07 16:41:47 +0200
///
/// \copyright  Copyright (C) 2015 - 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Logger class
///

#pragma once


#include <csl/util/string.h>
#include <csl/util/byte_array.h>
#include <csl/util/exception.h>
#include <csl/util/fthrow.h>
#include <csl/util/xml_util.h>

#include <base/capability.h>
#include <base/stdint.h>
#include <base/rpc_args.h>
#include <session/session.h>
#include <log_session/log_session.h>
#include <log_session/connection.h>



///
///  Reimplementation of the strncat feature
///
//char*
//strncat( char *dest, const char *src, size_t n );

namespace Csl
{

	class Output_repeat_filter
	{
		private:
			static const size_t MAX_TRESHOLD = 10000ull;
			size_t _base_treshold;
			size_t _treshold;
			size_t _seen;
			string _last_message;
			bool _enabled;

			void _reset( const string &new_message )
			{
				if ( _seen > 1 )
				{
					_report();
				}

				_treshold = _base_treshold;
				_seen = 1;
				_last_message = new_message;
			}

			void _report()
			{
				static size_t reached_max_treshold = 0;

				if ( _seen >= MAX_TRESHOLD )
				{
					++reached_max_treshold;
				}

				// Once the MAX_TRESHOLD is reached 5 times, give up repeating the message
				if ( 5 < reached_max_treshold )
				{
					return;
				}

				Genode::printf( "Message repeated %zu times.\n", _seen );
			}

			void _update_treshold()
			{

				_treshold *= 10;

				if ( _treshold > MAX_TRESHOLD )
				{
					_treshold = MAX_TRESHOLD;
				}
			}

			void _handle_duplicate()
			{
				++_seen;

				if ( _seen >= _treshold )
				{
					_report();
					_seen = 0;
					_update_treshold();
				}
			}

			Output_repeat_filter( size_t base_treshold = 1 ):
				_base_treshold( base_treshold ), _enabled( false )
			{
				_reset( "" );
			}

		public:
			void print( const Csl::string &message )
			{

				if ( not is_enabled() )
				{
					return Genode::printf( "%s", message.c_str() );
				}


				if ( _last_message == message )
				{
					return _handle_duplicate();
				}

				_reset( message );
			}

			void enable()
			{
				_enabled = true;
			}
			void disable()
			{
				_enabled = false;
			}
			bool is_enabled() const
			{
				return _enabled;
			}

			static Output_repeat_filter &instance()
			{
				static Output_repeat_filter inst;
				return inst;
			}
	};

	///
	/// Some log helper functionality
	///
	class Log_helper
	{
		public:
			enum Level {trace, debug, info, warn, error, fatal, wtf, assertlog, off};
			/// Convert a Log::Level enum value to a human readable char*
			///
			/// \param level to be converted to a char*
			///
			/// \return human readable char*
			///
			static const char *level_str( const Log_helper::Level level )
			{
				return _s()[level];
			}

			///
			/// Exception
			///
			EXCEPTION( Log_no_such_log_level );

			/// Convert char* to Log_helper::Level
			///
			/// \param str representation of the log level
			///
			/// \return The Log_helper::Level
			///
			static Log_helper::Level str_level( const char *str )
			{
				for ( int level = trace; level <= off; ++level )
					if ( 0 == strcmp( str,_s()[level] ) )
					{
						return Level( level );
					}

				fthrow<Log_no_such_log_level>( "No such log level: '%s'", str );
				return Log_helper::Level::off;
			}

			static const char *color( Log_helper::Level level )
			{
				static const char *colors[] =
				{
					"\033[1;97m", // white - trace
					"\033[1;97m", // white - debug
					"\033[1;92m", // green - info
					"\033[1;93m", // warn  - yellow
					"\033[1;91m", // error - red
					"\033[1;91m", // fatal - red
					"\033[1;95m", // wtf - pink
					"\033[1;91m", // assertlog - red
					"\033[1;90m" // darkgrey - off (probably never used.)
				};
				return colors[level];
			}

#define COLOR_END  "\033[0m"

		private:
			///
			/// String array of log levels (workaround for headerfile
			/// initialization
			///
			/// \return All loglevel strings.
			///
			static const  char **_s()
			{
				static const char *levels[] = {"trace", "debug", "info",
				                               "warn", "error", "fatal", "wtf", "assert", "off"
				                              };
				return levels;
			}
	};

	class Formatting_error {};

	/// Helper function in order to avoid whitespace lines being printed
	/// due to trailing '\n' values;
	///
	/// \param s the string to be trimmed
	///
	static void _remove_trailing_whitespace( Csl::string &s )
	{
		auto p = s.find_last_not_of( " \t\n\r" );

		if ( Csl::string::npos != p )
		{
			s.erase( p+1 );
		}
	}

	///
	/// Formats log lines for development purposes (more verbose with lines, metods, and files)
	///
	struct Development_output
	{

		/// Format input
		///
		/// \param module Module which is logging
		/// \param file Where the log is innitiated. Usually __FILE__
		/// \param line Where the log is innitiated. Usually __LINE__
		/// \param function Where the log is innitiated. Usually __PRETTY_FUNCTION__
		/// \param level Level of the log message.
		/// \param fmt Format string of the message.
		/// \param args Arguments to format string.
		///
		static void output( const char *const module,
		                    const char *const file,
		                    uint32_t line,
		                    const char *const function,
		                    Log_helper::Level level,
		                    const char *fmt,
		                    va_list &args )
		{
			Csl::string message = Csl::vsprintf( Csl::string( fmt ), args );
			_remove_trailing_whitespace( message );
			Output_repeat_filter::instance().print( Csl::sprintf( "[%7s] -%s %5s" COLOR_END
			                                        " - %s:%i:%s - %s\n",
			                                        module, Log_helper::color( level ), Log_helper::level_str( level ),
			                                        file, line, function,message.c_str() ) );
		}
	};

	///
	/// Poduction logging, only showing functional information.
	///
	struct Production_output
	{

		/// \see Development_output::output
		///
		static void output( const char *const module,
		                    const char *const file,
		                    uint32_t line,
		                    const char *const function,
		                    Log_helper::Level level,
		                    const char *fmt,
		                    va_list &args )
		{

			Csl::string message = Csl::vsprintf( Csl::string( fmt ), args );
			_remove_trailing_whitespace( message );
			Output_repeat_filter::instance().print( Csl::sprintf( "[%7s] -%s %5s" COLOR_END
			                                        " - %s\n",
			                                        module, Log_helper::color( level ), Log_helper::level_str( level ),
			                                        message.c_str() ) );
		}
	};


	template <class CHILD>
	class Labeled_log_output
	{
		private:
			struct Labeled_log_connection : Genode::Connection<Genode::Log_session>,
					Genode::Log_session_client
			{
				private:
					static const Csl::string _connection_string()
					{
						return Csl::sprintf( "ram_quota=8192, label=\"%s\"", CHILD::LABEL );
					}

				public:
					Labeled_log_connection( Genode::Env &env ):
						Connection<Log_session>( env,
						                         session( env.parent(), _connection_string().c_str() ) ),
						Log_session_client( cap() )
					{ }

					Labeled_log_connection(): Connection<Log_session>
						( session( _connection_string().c_str() ) ), Log_session_client( cap() )
					{
					}
			};

		public:
			static void output( const char *const module,
			                    const char *const file,
			                    uint32_t line,
			                    const char *const function,
			                    Log_helper::Level level,
			                    const char *fmt,
			                    va_list &args )
			{
				static Labeled_log_connection log_connection;


				Csl::string message = Csl::vsprintf( Csl::string( fmt ), args );
				_remove_trailing_whitespace( message );

				Csl::string formatted = Csl::sprintf( "[%7s] - %5s"
				                                      " - %s",
				                                      module,
				                                      Log_helper::level_str( level ),
				                                      message.c_str() );

				for ( size_t i = 0; i < formatted.length();
				        i += ( Genode::Log_session::String::MAX_SIZE - 1 ) )
				{

					Csl::Byte_array<Genode::Log_session::String::MAX_SIZE> prepared;

					const size_t minlen = min( prepared.capacity(), formatted.length() + 1 - i );
					Genode::strncpy( prepared.val, formatted.data() + i, minlen );

					Genode::Log_session::String o( prepared.val );

					log_connection.write( o );
				}
			}
	};

	struct Snmp_trap_output: public Labeled_log_output<Snmp_trap_output>
	{
		static constexpr const char *const LABEL = "snmp_trap";
	};



	///
	/// Silence
	///
	struct No_output
	{
		/// \see Development_output::output
		///
		/// \param module
		/// \param file
		/// \param line
		/// \param function
		/// \param level
		/// \param fmt
		/// \param args
		///

		static void output( const char *const module,
		                    const char *const file,
		                    uint32_t line,
		                    const char *const function,
		                    Log_helper::Level level,
		                    const char *fmt,
		                    va_list &args )
		{
		}
	};

#ifdef QUIET
	typedef No_output Std_output;
#elif defined(DEVELOPMENT)
	typedef Development_output Std_output;
#else
	typedef Production_output
	Std_output; ///!< Std_output is used by  many of the convenience macros.
#endif

	class Abstract_logger
	{

		public:
			Abstract_logger( Log_helper::Level level ):
				_level( level )
			{
			}

			/// Set the module name
			///
			///
			static constexpr const char *const MODULE_NAME = "abstract";

			///
			/// Get the module name
			///
			/// \return module name
			///
			virtual const char *module()
			{
				return MODULE_NAME;
			}

			/// Set the log level
			///
			/// \param level The log level.
			///
			void level( Log_helper::Level level )
			{
				_level = level;
			}

			///
			/// Define the various log functions, for the corresponding log-levels.
			///
			/// Note that it is probably easier to use the convenience Macros at the end of this file for logging.
			///
#define DEFLOGFN(lvl) void lvl(const char * const file,			\
	uint32_t line,							\
	const char * const function,					\
	const Csl::string &fmt,						\
	...) {								\
	va_list l;							\
	va_start(l, fmt);						\
	_log(file,line,function,Log_helper::Level::lvl,fmt.c_str(), l);	\
	va_end(l);							\
	}							        \
	bool lvl(){ return Log_helper::Level::lvl >= _level;  }

			DEFLOGFN( fatal )
			DEFLOGFN( wtf )
			DEFLOGFN( assertlog )
			DEFLOGFN( error )
			DEFLOGFN( warn )
			DEFLOGFN( info )
			DEFLOGFN( debug )
			DEFLOGFN( trace )

		protected:
			virtual void _log( const char *const file,
			                   uint32_t line,
			                   const char *const function,
			                   Log_helper::Level level,
			                   const char *fmt,
			                   va_list &args ) = 0;


			Log_helper::Level _level; ///!< current log level
	};

	///
	/// Logging functionality.
	///
	/// \param L Logging class which specifies the logging name.
	/// \param O Output which specifies how output should be formatted and generated.
	///
	template <typename L, typename O = Std_output>
	class Logger: public Abstract_logger
	{
		public:
			///
			/// Access the instance
			///
			/// \return the single logger instance
			///
			static Logger &instance()
			{
				static Logger l( Log_helper::Level::info );
				return l;
			}

			virtual const char *module()
			{
				return L::MODULE_NAME;
			}
		protected:
			/// Logging function that logs (or not) depending on the loglevel.
			///
			/// \param file From which log is innitiated.
			/// \param line From which log is innitiated.
			/// \param function From which log is innitiated.
			/// \param level
			/// \param fmt Format string of log
			/// \param args arguments of log line.
			///
			void _log( const char *const file,
			           uint32_t line,
			           const char *const function,
			           Log_helper::Level level,
			           const char *fmt,
			           va_list &args )
			{
				if ( level >= _level )
				{
					O::output( L::MODULE_NAME,file, line, function, level, fmt, args );
				}
			}

			Logger( Log_helper::Level level ):
				Abstract_logger( level )

			{}
	};
	namespace Log
	{
		///
		/// The standard logger for convenience functions
		///

		struct Std: public Logger<Std>
		{
			static constexpr const char *const MODULE_NAME = "std";
		};

		struct Network: public Logger<Network>
		{
			static constexpr const char *const MODULE_NAME = "network";
		};

		struct Crypto: public Logger<Crypto>
		{
			static constexpr const char *const MODULE_NAME = "crypto";
		};

		struct Job: public Logger<Job>
		{
			static constexpr const char *const MODULE_NAME = "job";
		};


		struct Snmp_trap: public Logger<Snmp_trap, Snmp_trap_output>
		{
			static constexpr const char *const MODULE_NAME = "trap";
		};
	}

	class Log_factory
	{
		public:
			EXCEPTION( Log_manager_exception );
			EXCEPTIONS( Log_manager_logger_not_found_exception, Log_manager_exception );

			static Log_factory &instance()
			{
				static Log_factory factory;
				return factory;
			}

			Abstract_logger &get( const char *const name )
			{
				for ( Abstract_logger *logger: _loggers )
				{
					if ( 0 == strcmp( logger->module(), name ) )
					{
						return *logger;
					}
				}

				fthrow<Log_manager_logger_not_found_exception>( "Unknown log manager: '%s'",
				        name );
				return *_loggers[0];
			}

			void level( Log_helper::Level level )
			{
				for ( auto logger : _loggers )
				{
					logger->level( level );
				}
			}
		private:
			Log_factory()
			{
				_loggers[0] = &Log::Std::instance();
				_loggers[1] = &Log::Network::instance();
				_loggers[2] = &Log::Crypto::instance();
				_loggers[3] = &Log::Job::instance();
			}
			// !!! do not forget to set the number of loggers below
			Abstract_logger *_loggers[4];
	};

	///
	/// Inits CSL Logging facilities, setting the loglevels as
	/// set in the configuration.
	///
	///
	/// Sample configuration:
	///
	/// .... snipped enclosing genode config ...
	/// <csl>
	///   <logging filter_duplicate_messages="true">
	///     <logger name="main" level="fatal"/>
	///     <logger name="network" level="fatal"/>
	///     <logger name="crypto" level="off"/>
	///   </logging>
	/// </csl>
	/// .... snipped enclosing genode config ...
	///
	void init_logging( const Genode::Xml_node &rootnode );

} // namespace Csl

#define ALOG(fmt, ...) if( Csl::Log::Std::instance().assertlog() ) \
	Csl::Log::Std::instance().assertlog(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define AMLOG(M,fmt, ...) if( M::instance().assertlog() ) \
	M::instance().assertlog(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define FLOG(fmt, ...) if( Csl::Log::Std::instance().fatal() ) \
	Csl::Log::Std::instance().fatal(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define FMLOG(M,fmt, ...) if( M::instance().fatal() ) \
	M::instance().fatal(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define ELOG(fmt, ...) if( Csl::Log::Std::instance().error() ) \
	Csl::Log::Std::instance().error(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define EMLOG(M,fmt, ...) if( M::instance().error() ) \
	M::instance().error(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define WLOG(fmt, ...) if( Csl::Log::Std::instance().warn() ) \
	Csl::Log::Std::instance().warn(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define WMLOG(M,fmt, ...) if( M::instance().warn() ) \
	M::instance().warn(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define ILOG(fmt, ...) if( Csl::Log::Std::instance().info() ) \
	Csl::Log::Std::instance().info(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define IMLOG(M,fmt, ...) if( M::instance().info() ) \
	M::instance().info(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define DLOG(fmt, ...) if( Csl::Log::Std::instance().debug() ) \
	Csl::Log::Std::instance().debug(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define DMLOG(M,fmt, ...) if( M::instance().debug() ) \
	M::instance().debug(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define TLOG(fmt, ...) if( Csl::Log::Std::instance().trace() ) \
	Csl::Log::Std::instance().trace(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )
#define TMLOG(M,fmt, ...) if( M::instance().trace() ) \
	M::instance().trace(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )

#define WTF(fmt, ...) if( Csl::Log::Std::instance().wtf() ) \
		Csl::Log::Std::instance().wtf(__FILE__, __LINE__, __PRETTY_FUNCTION__, fmt, ##__VA_ARGS__ )

template<class E>
inline void log_and_throw( const char *fmt, ... )
{
	va_list args;
	va_start( args,fmt );
	auto w = Csl::vsprintf( fmt, args );
	va_end( args );
	ELOG( w.c_str() );
	throw E( w.c_str() );
}

