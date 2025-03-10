#ifndef __IRODS_ERROR_HPP__
#define __IRODS_ERROR_HPP__

// =-=-=-=-=-=-=-
// STL Includes
#include <string>
#include <vector>
#include <cstdarg>

#include <boost/optional.hpp>

// =-=-=-=-=-=-=-
// irods includes
#include "irods/rodsType.h"
#include "irods/irods_exception.hpp"

#include <boost/assert.hpp>
#include <boost/format.hpp>

namespace irods {
/// =-=-=-=-=-=-=-
/// @brief error stack object which holds error history
    class error {
        public:
            // =-=-=-=-=-=-=-
            // Constructors
            error();
            error(
                bool,          // status
                long long,     // error code
                std::string,   // message
                std::string,   // file name
                int,           // line number
                std::string ); // function
            error(
                bool,          // status
                long long,     // error code
                boost::format, // message
                std::string,   // file name
                int,           // line number
                std::string ); // function
            error(                  // deprecated since 4.0.3
                bool,           // status
                long long,      // error code
                std::string,    // message
                std::string,    // file name
                int,            // line number
                std::string,    // function
                const error& ); // previous error
            error(
                std::string,    // message
                std::string,    // file name
                int,            // line number
                std::string,    // function
                const error& ); // previous error
            error( const error& );
            error( const exception& );

            // =-=-=-=-=-=-=-
            // Destructor
            ~error();

            // =-=-=-=-=-=-=-
            // Operators
            error& operator=( const error& );

            // =-=-=-=-=-=-=-
            // Members
            bool        status() const;
            long long   code() const;
            std::string result() const;
            std::string user_result() const;
            bool        ok();          // deprecated since 4.0.3
            bool        ok() const;

            // =-=-=-=-=-=-=-
            // Mutators
            void code( long long _code ) {
                code_   = _code;
            }
            void status( bool      _status ) {
                status_ = _status;
            }
            void message( const std::string& _message ) {
                message_ = _message;
            }

        private:
            // =-=-=-=-=-=-=-
            // Attributes
            bool        status_;
            long long   code_;
            std::string message_;
            std::vector< std::string > result_stack_;
            boost::optional< exception > exception_;

            // These are hard-coded strings that are used in creating
            // the strings that go in result_stack_, and that are searched
            // for as such.  See static declarations in irods_error.cpp for initialization.
            static const char *iRODS_token_;
            static const char *colon_token_;
            static const char *status_token_;

            // =-=-=-=-=-=-=-
            // Members
            std::string build_result_string( std::string, int, std::string );

    }; // class error
}; // namespace irods

#define ERROR( code_, message_ ) ( irods::error( false, code_, message_, __FILE__, __LINE__, __PRETTY_FUNCTION__ ) ) // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
#define PASS( prev_error_ ) (irods::error( "", __FILE__, __LINE__, __PRETTY_FUNCTION__, prev_error_ ) ) // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
#define PASSMSG( message_, prev_error_ ) (irods::error( message_, __FILE__, __LINE__, __PRETTY_FUNCTION__, prev_error_ ) ) // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
#define CODE( code_ ) ( irods::error( true, code_, "", __FILE__, __LINE__, __PRETTY_FUNCTION__ ) ) // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
#define SUCCESS( ) ( irods::error( true, 0, "", __FILE__, __LINE__, __PRETTY_FUNCTION__ ) ) // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

#endif // __IRODS_ERROR_HPP__
