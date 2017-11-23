///
/// \file       file_wrapper.h
/// \author     Martijn Verschoor <verschoor@nlcsl.com>
/// \author     Menno Valkema <menno.valkema@nlcsl.com>
/// \date       2016-09-22
///
/// \copyright  Copyright (C) 2016 Cyber Security Labs B.V. The Netherlands.
///
/// \license    This file is part of libcsl, which is distributed
///             under the terms of the GNU Affero General Public License version 3.
///
/// \brief      Convenience class for writing files
///

#pragma once

// CSL includes
#include <csl/util/assert.h>
#include <csl/util/logger.h>
#include <csl/util/data_descriptor.h>

// Genode includes
#include <base/heap.h>
#include <file_system_session/connection.h>
#include <file_system/util.h>
#include <os/path.h>

class File_wrapper
{
	private:
		File_system::Session &_fs;

		enum { PATH_MAX_LEN = 512 };
		typedef Genode::Path<PATH_MAX_LEN> Path;

		/**
		 * Name of requested file, interpreted at path into the file system
		 */
		Path const _file_path;

		/**
		 * Handle of associated file
		 */
		File_system::File_handle _file_handle;

		/**
		 * Open compound directory of specified file
		 *
		 * \param walk_up  If set to true, the function tries to walk up the
		 *                 hierarchy towards the root and returns the first
		 *                 existing directory on the way. If set to false, the
		 *                 function returns the immediate compound directory.
		 */
		static File_system::Dir_handle _open_compound_dir( File_system::Session &fs,
		        Path const &path,
		        bool walk_up )
		{
			using namespace File_system;

			Genode::Path<PATH_MAX_LEN> dir_path( path.base() );

			while ( !path.equals( "/" ) )
			{

				dir_path.strip_last_element();

				try
				{
					return fs.dir( dir_path.base(), false );
				}
				catch ( ... )
				{
					fthrow<Csl::Exception>( "Unable to create directory." );
				}


				/*
				 * If the directory could not be opened, walk up the hierarchy
				 * towards the root and try again.
				 */
				if ( !walk_up )
				{
					break;
				}
			}

			cslassert( false );
			return Dir_handle(); /* invalid */
		}

		/**
		 * Open file with specified name at the file system
		 */
		static File_system::File_handle _open_file( File_system::Session &fs,
		        Path const &path )
		{
			using namespace File_system;

			File_system::File_handle file_handle;

			try
			{

				Dir_handle dir = _open_compound_dir( fs, path, false );
				Handle_guard guard( fs, dir );

				/* open file */
				Genode::Path<PATH_MAX_LEN> file_name( path.base() );
				file_name.keep_only_last_element();
				file_handle = fs.file( dir, file_name.base() + 1,
				                       File_system::READ_WRITE, false );
				return file_handle;
			}
			catch ( ... )
			{
				PERR( "failed to create file" );
				throw;
			}
		}

	public:

		File_wrapper( File_system::Session &fs, const char *file_path )
			:
			_fs( fs ), _file_path( file_path ), _file_handle( _open_file( _fs,
			        _file_path ) )
		{
		}

		~File_wrapper()
		{
			_fs.close( _file_handle );
		}

		void write( Csl::string contents )
		{
			if ( !_file_handle.valid() )
			{
				ELOG( "file handle unvalid" );
			}
			else
			{
				try
				{
					File_system::write( _fs, _file_handle, contents.data(), contents.size() );
					_fs.truncate( _file_handle, contents.size() );
				}
				catch ( ... )
				{
					ELOG( "Some exception " );
					throw;

				}
			}
		}

		void read( Csl::Data_descriptor_mod &dd )
		{
			if ( !_file_handle.valid() )
			{
				ELOG( "file handle unvalid" );
			}
			else
			{
				try
				{
					size_t size;
					size = File_system::read( _fs, _file_handle, dd.data(), dd.size() );
					dd = dd.reduce( size );
				}
				catch ( ... )
				{
					ELOG( "Some exception " );
					throw;
				}
			}
		}
};

