# iRODS passwords for native authentication are stored in the iRODS catalog in "scrambled" form, which uses the MD5
# algorithm as part of its encoding process. For some standards (e.g. FIPS), MD5 is non-compliant and cannot be used.
# Starting in iRODS 5.1, passwords are scrambled using SHA256 instead of MD5 before storing in the catalog.
#
# This script is meant to run after upgrading to iRODS 5.1 or later in order to re-scramble passwords stored in the
# iRODS catalog using SHA256 instead of MD5. It is not required to run this script as MD5-based scrambled passwords
# are still understood by the database plugin.

import argparse
import contextlib
import hashlib
import logging
import sys
import textwrap

import irods.lib
from irods import database_connect, database_interface, password_obfuscation
from irods.configuration import IrodsConfig


class HashScheme:
    def __init__(self, scheme_name, hash_func, scramble_prefix):
        self._hash_func = hash_func
        self._scramble_prefix = scramble_prefix
        self._scheme_name = scheme_name

    @property
    def hash_func(self):
        return self._hash_func

    @hash_func.setter
    def hash_func(self, hash_func):
        self._hash_func = hash_func

    @property
    def scramble_prefix(self):
        return self._scramble_prefix

    @scramble_prefix.setter
    def scramble_prefix(self, scramble_prefix):
        self._scramble_prefix = scramble_prefix

    def scramble(self, s):
        return password_obfuscation.scramble(
            s, scramble_prefix=self.scramble_prefix, hash_func=self.hash_func
        )

    def unscramble(self, s):
        return password_obfuscation.unscramble(
            s, scramble_prefix=self.scramble_prefix, hash_func=self.hash_func
        ).replace("'", "''")

    def __str__(self):
        return self._scheme_name

    def __repr__(self):
        return self._scheme_name


sha256_scheme = HashScheme(
    "sha256", hashlib.sha256, password_obfuscation.sha256_scramble_prefix
)


md5_scheme = HashScheme("md5", hashlib.md5, password_obfuscation.md5_scramble_prefix)


hash_func_map = {str(md5_scheme): md5_scheme, str(sha256_scheme): sha256_scheme}


def configure_logging(verbosity):
    level = logging.CRITICAL - 10 * verbosity
    handlers = [logging.StreamHandler(sys.stdout)]
    logging.basicConfig(
        level=level if level > logging.NOTSET else logging.DEBUG,
        format="%(asctime)-15s - %(message)s",
        handlers=handlers,
    )


def get_update_condition(input_scheme):
    return f"rcat_password LIKE '{input_scheme.scramble_prefix}%'"


def get_updateable_row_count(cursor, input_scheme):
    count_rows_to_update = f"SELECT COUNT(*) FROM r_user_password WHERE {get_update_condition(input_scheme)};"
    return int(
        database_connect.execute_sql_statement(cursor, count_rows_to_update).fetchone()[
            0
        ]
    )


def update_rows(connection, input_scheme, output_scheme, batch_size=500, dry_run=False):
    with contextlib.closing(connection.cursor()) as cursor:
        initial_count_of_rows_to_update = get_updateable_row_count(cursor, input_scheme)
        try:
            if 0 == initial_count_of_rows_to_update:
                print("No rows will be updated. Exiting...")
                return

            rows_updated = 0

            if dry_run:
                print("This is a dry run. No rows will actually be updated.")

            print("Rows to update: {}".format(initial_count_of_rows_to_update))
            user_input = irods.lib.default_prompt(
                "Would you like to continue?", default=["No"]
            )
            if "y" != user_input.lower() and "yes" != user_input.lower():
                print("User declined. Exiting...")
                return

            select_passwords = f"SELECT rcat_password from R_USER_PASSWORD WHERE {get_update_condition(input_scheme)};"

            while batch := database_connect.execute_sql_statement(
                cursor, select_passwords
            ).fetchmany(batch_size):
                if dry_run and rows_updated >= initial_count_of_rows_to_update:
                    break

                for row in batch:
                    password = row.rcat_password

                    logging.debug(f"password:{password}")

                    # Skip passwords which do not start with the prefix... which should be none because we filtered on that...
                    if not password.startswith(input_scheme.scramble_prefix):
                        logging.warning(
                            f"Skipping password '{password}'. Does not start with '{input_scheme.scramble_prefix}'."
                        )
                        continue

                    # Need to escape single quotes before feeding it to the update statement.
                    rescrambled_password = output_scheme.scramble(
                        input_scheme.unscramble(password)
                    ).replace("'", "''")
                    pw = password.replace("'", "''")

                    update_statement = f"UPDATE R_USER_PASSWORD SET rcat_password = '{rescrambled_password}' WHERE rcat_password = '{pw}';"
                    logging.info(f"Executing: {update_statement}")
                    if not dry_run:
                        database_connect.execute_sql_statement(cursor, update_statement)

                logging.debug(f"{batch_size} rows updated... committing...")
                if not dry_run:
                    connection.commit()
                rows_updated += len(batch)

            logging.debug("Final commit...")
            if dry_run:
                # If the dry run was not interrupted, the row count can just be set to however many rows were supposed
                # to have been updated. Otherwise, the count will be the batch_size multiplied by the number of fetches
                # that occurred, which may be incorrect.
                rows_updated = total_rows_updated_count = (
                    initial_count_of_rows_to_update
                )
                remaining_rows_to_update = 0
            else:
                connection.commit()
                remaining_rows_to_update = get_updateable_row_count(
                    cursor, input_scheme
                )
                total_rows_updated_count = int(
                    initial_count_of_rows_to_update - remaining_rows_to_update
                )

        except (KeyboardInterrupt, SystemExit):
            if dry_run:
                total_rows_updated_count = rows_updated
                remaining_rows_to_update = (
                    initial_count_of_rows_to_update - rows_updated
                )
            else:
                connection.rollback()
                remaining_rows_to_update = get_updateable_row_count(
                    cursor, input_scheme
                )
                total_rows_updated_count = int(
                    initial_count_of_rows_to_update - remaining_rows_to_update
                )
            print("\nExiting...")

        print("Total rows updated: {}".format(total_rows_updated_count))
        print("Remaining rows to update: {}".format(remaining_rows_to_update))
        if dry_run:
            print("This is a dry run. No rows were actually updated.")


def rescramble_main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """\
            Replace passwords stored in the iRODS catalog which are scrambled using the historical
            MD5-based scheme with passwords scrambled using a SHA256-based scheme.

            WARNING: This script directly overwrites data in the iRODS Catalog. Make sure catalog
            is backed up before proceeding. This script must be run on the catalog provider."""
        ),
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Count rows to be overwritten (no changes made to database)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        dest="verbosity",
        action="count",
        default=1,
        help=textwrap.dedent(
            """\
            Increase the level of output to stdout. \
            CRITICAL and ERROR messages will always be printed. \
            Add more to see more log messages (e.g. -vvv displays DEBUG)."""
        ),
    )
    parser.add_argument(
        "-i",
        "--input-scheme",
        action="store",
        dest="input_scheme",
        type=str,
        default="md5",
        help='The hash scheme name to target for rescrambling (default: "md5").',
    )
    parser.add_argument(
        "-o",
        "--output-scheme",
        action="store",
        dest="output_scheme",
        type=str,
        default="sha256",
        help='The hash scheme name to use for rescrambling (default: "sha256").',
    )
    parser.add_argument(
        "-b",
        "--batch-size",
        action="store",
        dest="batch_size",
        type=int,
        default=500,
        help="Number of records to update per database commit (default: 500)",
    )
    # TODO: Could be useful as a non-destructive option. Will require some work though.
    # parser.add_argument(
    #     '--do-not-overwrite', action='store_false', dest='overwrite', default=True,
    #     help='If specified, new passwords will be inserted alongside the existing ones instead of overwriting them.')
    # TODO: Options to limit to certain user names or types could be good. Regex filter.
    # TODO: Options to skip passwords which have an expiration time.
    # TODO: Options to purge passwords which have an expiration time.
    args = parser.parse_args()

    configure_logging(args.verbosity)

    input_scheme = args.input_scheme.lower()
    if input_scheme not in hash_func_map:
        print(
            f"Unsupported input scheme [{args.input_scheme}]. Supported schemes: {', '.join([k for k in hash_func_map])}"
        )
        return 1

    output_scheme = args.output_scheme.lower()
    if output_scheme not in hash_func_map:
        print(
            f"Unsupported output scheme [{args.output_scheme}]. Supported schemes: {', '.join([k for k in hash_func_map])}"
        )
        return 1

    if input_scheme == output_scheme:
        print("Input scheme and output scheme are the same. Nothing to do.")
        return 0

    with contextlib.closing(
        database_connect.get_database_connection(IrodsConfig())
    ) as connection:
        connection.autocommit = False
        update_rows(
            connection,
            hash_func_map[input_scheme],
            hash_func_map[output_scheme],
            batch_size=args.batch_size,
            dry_run=args.dry_run,
        )


if __name__ == "__main__":
    exit(rescramble_main())
