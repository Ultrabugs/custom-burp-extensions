# -*- coding: utf-8 -*-
# SQLi Tester v4 - Burp Suite Extension
#
# New in v4 - a host import queues everything the host has:
#   * The three filters the import used to apply unconditionally - skipping
#     static files, skipping requests with nothing in scope to inject, and
#     collapsing an endpoint to one entry per injection surface - are now
#     checkboxes under SITE MAP IMPORT in Settings, all off by default. With
#     de-duplication off only byte-identical requests are dropped, so /s?q=1
#     and /s?q=2 both land in the queue. The per-invocation cap is 5000, was 500.
#   * A queued request with no parameter in any ticked class simply contributes
#     no probes, so queueing it costs nothing but a row.
#   * "Clear everything on new Send" (Settings > SITE MAP IMPORT, on by
#     default): each new "Send to SQLi Tester v4" wipes the queue, the Results
#     tab and the Findings tab first, so you start clean without clicking Clear
#     on each. Turn it off to build one queue from several hosts. The choice is
#     saved with the other settings.
#
# New in v3 - site map import:
#   * "Send whole host(s) from site map to SQLi Tester v4" on the right-click
#     menu. Highlight one or more hosts in the Site map (or any request under
#     them) and every request Burp has recorded for those hosts is queued
#     recursively. Static files, endpoints with nothing in the current scope to
#     inject into, and repeats of an injection surface already queued are
#     dropped; the status bar and console say what was skipped and why.
#
# New in v3 - the results table keeps up with the scan now:
#   * One UI refresh every 120 ms instead of one per request. Worker threads
#     queue rows and findings updates; a single timer on the EDT flushes the
#     batch. v2 posted an invokeLater per request, and with threads turned up
#     that is thousands of events, each one re-sorting the table - the scan ran
#     fine but the table fell behind and looked stuck.
#   * Findings rows are found through an id -> row index map. v2 walked the
#     whole findings model on the EDT for every repeat of every signal, which
#     on a noisy endpoint is quadratic work in the paint thread.
#   * The search box no longer fights the live rows. v2 rebuilt the table from
#     its row list while threads appended straight into the model, so a single
#     keystroke mid-scan left duplicates, non-matching rows, and a count that
#     matched nothing. The query is applied to new rows as they arrive.
#   * The table stays sorted by #, so rows finishing out of order across
#     threads no longer look shuffled or missing.
#   * Honest counters. The bar reads "probes done / total | requests sent |
#     rows", with "shown of N" while a search is active, and the final line
#     reports probes, requests actually sent (baselines and time re-tests
#     included - v2 counted neither), rows held, and anything not run because
#     Stop was pressed.
#
# Differences from v1:
#   * pick exactly which classes of parameter to scan - URL (GET), body (POST
#     form or JSON), headers, cookies - each independently
#   * "Simple Scan" fires a single ' at every parameter and nothing else, for
#     WAF-heavy targets; same regex error / 5xx reporting, no sleeps
#   * "Full Scan" is the normal run: the whole payload list, time-based
#     detection and re-test confirmation
# Install: Extender > Extensions > Add > Type: Python > Select this file
# Requires: Jython standalone JAR configured in Extender > Options > Python Environment

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
from javax.swing import (
    JPanel, JTabbedPane, JTable, JScrollPane, JButton, JLabel,
    JTextField, JCheckBox, JTextArea, JSplitPane, JMenuItem,
    SwingUtilities, BorderFactory, JProgressBar, Box,
    JRadioButton, ButtonGroup, ListSelectionModel, Timer, RowSorter, SortOrder,
    JTree
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.text import DefaultHighlighter
from java.awt.event import ActionListener
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.util import ArrayList, Comparator
import java.lang
import threading
import time
import re

# How often the UI is refreshed while a scan runs.  One repaint every DRAIN_MS
# instead of one per request: with 50 threads the old per-request approach put
# thousands of events on the EDT, each re-sorting the table and walking the
# findings model, and the table could not keep up with the scan.
DRAIN_MS = 120

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
BG      = Color(28,  28,  36)
BG2     = Color(38,  38,  50)
BG3     = Color(50,  50,  65)
FG      = Color(220, 220, 230)
FG_DIM  = Color(140, 140, 160)
ACCENT  = Color(88,  166, 255)
GREEN   = Color(80,  200, 120)
RED     = Color(255, 80,  80)
YELLOW  = Color(255, 200, 60)
BORDER  = Color(60,  60,  80)

PARAM_TYPE = {0: "URL", 1: "Body", 2: "Cookie", 3: "XML", 4: "XML-Attr", 5: "Multi", 6: "JSON"}
KIND_LABEL = {"url": "URL", "body": "Body", "json": "JSON", "cookie": "Cookie", "header": "Header"}

# ---------------------------------------------------------------------------
# Payloads  -  error provokers + time-based sleeps.  No boolean (1=1 / 1=2)
# differential testing: this build only reports SQL errors, 5xx / dead
# responses and measured delays.
# ---------------------------------------------------------------------------
SLEEP_SECS = 20          # default stall for the time payloads below
SIMPLE_PAYLOAD = "'"     # the only thing Simple Scan sends
RPS_CAP    = 4.0         # hard ceiling on requests/sec, scan + confirmations

# Payloads are written Burp-style: "+" stands in for a space, nothing is
# percent-encoded, and everything is single-quote based (JSON bodies rarely
# care about "). In a URL query string the server turns "+" back into a space;
# for JSON values the "+ = space (JSON)" box on the Scanner tab does it
# instead, since nothing url-decodes a JSON string.
DEFAULT_PAYLOADS = [
    # -- syntax breakers: make the parser complain ------------------------
    "'",
    "''",
    "')",
    "'))",
    "';",
    "'--",
    "'+AND+1=CONVERT(int,'x')--",
    "'+AND+1=CAST('x'+AS+int)--",
    "'+AND+1=TO_NUMBER('x')--",
    "'+AND+(SELECT+1+FROM+no_such_table_zq)--",
    "'+AND+EXTRACTVALUE(1,CONCAT(0x7e,0x5a))--",
    # -- time based: MySQL / MariaDB --------------------------------------
    "'+AND+SLEEP(20)--",
    "')+AND+SLEEP(20)--",
    "'+OR+SLEEP(20)--",
    "+AND+SLEEP(20)",
    "'+AND+BENCHMARK(30000000,MD5('a'))--",
    # -- time based: PostgreSQL -------------------------------------------
    "'+AND+pg_sleep(20)--",
    "';+SELECT+pg_sleep(20)--",
    "+AND+(SELECT+1+FROM+pg_sleep(20))+IS+NOT+NULL",
    # -- time based: MSSQL -------------------------------------------------
    "';+WAITFOR+DELAY+'0:0:20'--",
    "'+WAITFOR+DELAY+'0:0:20'--",
    "');+WAITFOR+DELAY+'0:0:20'--",
    # -- time based: Oracle ------------------------------------------------
    "'+AND+DBMS_PIPE.RECEIVE_MESSAGE('a',20)+IS+NOT+NULL--",
    # -- time based: SQLite (no sleep() - burn CPU instead) ----------------
    "'+AND+RANDOMBLOB(900000000)+IS+NOT+NULL--",
]

# ---------------------------------------------------------------------------
# DBMS error signatures: (engine, literal gate, regex).  The regex set is the
# nuclei / sqlmap error-based-sqli list plus driver and ORM signatures.
#
# The gate is the longest literal string that MUST appear in anything the regex
# can match, derived from the pattern itself.  Checking ~190 cheap substrings
# before running 212 regexes takes a 260 KB response from ~500 ms down to
# ~20 ms under Jython, with identical results.
# ---------------------------------------------------------------------------

SQL_ERROR_SIGNATURES = [
    # ---- MySQL ---------------------------------------------------------
    ("MySQL",         'sql syntax',              r"SQL syntax.{0,500}?MySQL"),
    ("MySQL",         'warning',                 r"Warning.{0,500}?\Wmysqli?_"),
    ("MySQL",         'mysqlsyntaxerrorexception', r"MySQLSyntaxErrorException"),
    ("MySQL",         'valid mysql result',      r"valid MySQL result"),
    ("MySQL",         ' your mysql server version', r"check the manual that (corresponds to|fits) your MySQL server version"),
    ("MySQL",         "' in 'field list'",       r"Unknown column '[^ ]+' in 'field list'"),
    ("MySQL",         'mysqlclient.',            r"MySqlClient\."),
    ("MySQL",         'com.mysql.jdbc',          r"com\.mysql\.jdbc"),
    ("MySQL",         '_mysqli_exception',       r"Zend_Db_(Adapter|Statement)_Mysqli_Exception"),
    ("MySQL",         'mysql',                   r"Pdo[./_\\]Mysql"),
    ("MySQL",         'mysqlexception',          r"MySqlException"),
    ("MySQL",         ']: syntax error or access violation', r"SQLSTATE\[\d+\]: Syntax error or access violation"),
    # ---- MariaDB -------------------------------------------------------
    ("MariaDB",       ' your mariadb server version', r"check the manual that (corresponds to|fits) your MariaDB server version"),
    # ---- Drizzle -------------------------------------------------------
    ("Drizzle",       ' your drizzle server version', r"check the manual that (corresponds to|fits) your Drizzle server version"),
    # ---- MemSQL --------------------------------------------------------
    ("MemSQL",        'memsql does not support this type of query', r"MemSQL does not support this type of query"),
    ("MemSQL",        'is not supported by memsql', r"is not supported by MemSQL"),
    ("MemSQL",        'unsupported nested scalar subselect', r"unsupported nested scalar subselect"),
    # ---- PostgreSQL ----------------------------------------------------
    ("PostgreSQL",    'postgresql',              r"PostgreSQL.{0,500}?ERROR"),
    ("PostgreSQL",    'warning',                 r"Warning.{0,500}?\Wpg_"),
    ("PostgreSQL",    'valid postgresql result', r"valid PostgreSQL result"),
    ("PostgreSQL",    'npgsql.',                 r"Npgsql\."),
    ("PostgreSQL",    'pg::syntaxerror:',        r"PG::SyntaxError:"),
    ("PostgreSQL",    'org.postgresql.util.psqlexception', r"org\.postgresql\.util\.PSQLException"),
    ("PostgreSQL",    'syntax error at or near', r"ERROR:\s\ssyntax error at or near"),
    ("PostgreSQL",    'error: parser: parse error at or near', r"ERROR: parser: parse error at or near"),
    ("PostgreSQL",    'postgresql query failed', r"PostgreSQL query failed"),
    ("PostgreSQL",    'org.postgresql.jdbc',     r"org\.postgresql\.jdbc"),
    ("PostgreSQL",    'pgsql',                   r"Pdo[./_\\]Pgsql"),
    ("PostgreSQL",    'psqlexception',           r"PSQLException"),
    # ---- MSSQL ---------------------------------------------------------
    ("MSSQL",         'driver',                  r"Driver.{0,500}? SQL[\-\_\ ]*Server"),
    ("MSSQL",         ' sql server',             r"OLE DB.{0,500}? SQL Server"),
    ("MSSQL",         'sql server',              r'\bSQL Server[^<"]+Driver'),
    ("MSSQL",         'warning',                 r"Warning.{0,500}?\W(mssql|sqlsrv)_"),
    ("MSSQL",         'sql server',              r'\bSQL Server[^<"]+[0-9a-fA-F]{8}'),
    ("MSSQL",         'system.data.sqlclient.sqlexception.sql', r"System\.Data\.SqlClient\.SqlException\.(SqlException|SqlConnection\.OnError)"),
    ("MSSQL",         'roadhouse.cms.',          r"Exception[\s\S]{0,500}?\bRoadhouse\.Cms\."),
    ("MSSQL",         "microsoft sql native client error '", r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}"),
    ("MSSQL",         '[sql server]',            r"\[SQL Server\]"),
    ("MSSQL",         'odbc sql server driver',  r"ODBC SQL Server Driver"),
    ("MSSQL",         ' for sql server',         r"ODBC Driver \d+ for SQL Server"),
    ("MSSQL",         'sqlserver jdbc driver',   r"SQLServer JDBC Driver"),
    ("MSSQL",         'com.jnetdirect.jsql',     r"com\.jnetdirect\.jsql"),
    ("MSSQL",         'macromedia.jdbc.sqlserver', r"macromedia\.jdbc\.sqlserver"),
    ("MSSQL",         '_sqlsrv_exception',       r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"),
    ("MSSQL",         'com.microsoft.sqlserver.jdbc', r"com\.microsoft\.sqlserver\.jdbc"),
    ("MSSQL",         '',                        r"Pdo[./_\\](Mssql|SqlSrv)"),
    ("MSSQL",         'exception',               r"SQL(Srv|Server)Exception"),
    ("MSSQL",         'unclosed quotation mark after the character string', r"Unclosed quotation mark after the character string"),
    # ---- MS Access -----------------------------------------------------
    ("MS Access",     'microsoft access ',       r"Microsoft Access (\d+ )?Driver"),
    ("MS Access",     'jet database engine',     r"JET Database Engine"),
    ("MS Access",     'access database engine',  r"Access Database Engine"),
    ("MS Access",     'odbc microsoft access',   r"ODBC Microsoft Access"),
    ("MS Access",     'syntax error (missing operator) in query expression', r"Syntax error \(missing operator\) in query expression"),
    # ---- Oracle --------------------------------------------------------
    ("Oracle",        'ora-',                    r"\bORA-\d{5}"),
    ("Oracle",        'oracle error',            r"Oracle error"),
    ("Oracle",        'oracle',                  r"Oracle.{0,500}?Driver"),
    ("Oracle",        'warning',                 r"Warning.{0,500}?\W(oci|ora)_"),
    ("Oracle",        'quoted string not properly terminated', r"quoted string not properly terminated"),
    ("Oracle",        'sql command not properly ended', r"SQL command not properly ended"),
    ("Oracle",        'macromedia.jdbc.oracle',  r"macromedia\.jdbc\.oracle"),
    ("Oracle",        'oracle.jdbc',             r"oracle\.jdbc"),
    ("Oracle",        '_oracle_exception',       r"Zend_Db_(Adapter|Statement)_Oracle_Exception"),
    ("Oracle",        '',                        r"Pdo[./_\\](Oracle|OCI)"),
    ("Oracle",        'oracleexception',         r"OracleException"),
    # ---- DB2 -----------------------------------------------------------
    ("DB2",           'cli driver',              r"CLI Driver.{0,500}?DB2"),
    ("DB2",           'db2 sql error',           r"DB2 SQL error"),
    ("DB2",           'db2_',                    r"\bdb2_\w+\("),
    ("DB2",           'sqlstate',                r"SQLCODE[=:\d, -]+SQLSTATE"),
    ("DB2",           'com.ibm.db2.jcc',         r"com\.ibm\.db2\.jcc"),
    ("DB2",           '_db2_exception',          r"Zend_Db_(Adapter|Statement)_Db2_Exception"),
    ("DB2",           '',                        r"Pdo[./_\\]Ibm"),
    ("DB2",           'db2exception',            r"DB2Exception"),
    ("DB2",           'ibm_db_dbi.programmingerror', r"ibm_db_dbi\.ProgrammingError"),
    # ---- Informix ------------------------------------------------------
    ("Informix",      'warning',                 r"Warning.{0,500}?\Wifx_"),
    ("Informix",      'exception',               r"Exception.{0,500}?Informix"),
    ("Informix",      'informix odbc driver',    r"Informix ODBC Driver"),
    ("Informix",      'odbc informix driver',    r"ODBC Informix driver"),
    ("Informix",      'com.informix.jdbc',       r"com\.informix\.jdbc"),
    ("Informix",      'weblogic.jdbc.informix',  r"weblogic\.jdbc\.informix"),
    ("Informix",      'informix',                r"Pdo[./_\\]Informix"),
    ("Informix",      'ifxexception',            r"IfxException"),
    # ---- Firebird ------------------------------------------------------
    ("Firebird",      'dynamic sql error',       r"Dynamic SQL Error"),
    ("Firebird",      'warning',                 r"Warning.{0,500}?\Wibase_"),
    ("Firebird",      'org.firebirdsql.jdbc',    r"org\.firebirdsql\.jdbc"),
    ("Firebird",      'firebird',                r"Pdo[./_\\]Firebird"),
    # ---- SQLite --------------------------------------------------------
    ("SQLite",        'sqlite/jdbcdriver',       r"SQLite/JDBCDriver"),
    ("SQLite",        'sqlite.exception',        r"SQLite\.Exception"),
    ("SQLite",        '.data.sqlite.sqliteexception', r"(Microsoft|System)\.Data\.SQLite\.SQLiteException"),
    ("SQLite",        'warning',                 r"Warning.{0,500}?\W(sqlite_|SQLite3::)"),
    ("SQLite",        'sqlite_error',            r"SQLITE_ERROR"),
    ("SQLite",        'sqlite error ',           r"SQLite error \d+:"),
    ("SQLite",        'operationalerror:',       r"sqlite3.OperationalError:"),
    ("SQLite",        'sqlite3::sqlexception',   r"SQLite3::SQLException"),
    ("SQLite",        'org.sqlite.jdbc',         r"org\.sqlite\.JDBC"),
    ("SQLite",        'sqlite',                  r"Pdo[./_\\]Sqlite"),
    ("SQLite",        'sqliteexception',         r"SQLiteException"),
    # ---- SAP MaxDB -----------------------------------------------------
    ("SAP MaxDB",     'sql error',               r"SQL error.{0,500}?POS([0-9]+)"),
    ("SAP MaxDB",     'warning',                 r"Warning.{0,500}?\Wmaxdb_"),
    ("SAP MaxDB",     'driversapdb',             r"DriverSapDB"),
    ("SAP MaxDB",     'invalid end of sql statement', r"-3014.{0,500}?Invalid end of SQL statement"),
    ("SAP MaxDB",     'com.sap.dbtech.jdbc',     r"com\.sap\.dbtech\.jdbc"),
    ("SAP MaxDB",     ': invalid keyword or missing delimiter', r"\[-3008\].{0,500}?: Invalid keyword or missing delimiter"),
    # ---- Sybase --------------------------------------------------------
    ("Sybase",        'warning',                 r"Warning.{0,500}?\Wsybase_"),
    ("Sybase",        'sybase message',          r"Sybase message"),
    ("Sybase",        'server message',          r"Sybase.{0,500}?Server message"),
    ("Sybase",        'sybsqlexception',         r"SybSQLException"),
    ("Sybase",        'sybase.data.aseclient',   r"Sybase\.Data\.AseClient"),
    ("Sybase",        'com.sybase.jdbc',         r"com\.sybase\.jdbc"),
    # ---- Ingres --------------------------------------------------------
    ("Ingres",        'warning',                 r"Warning.{0,500}?\Wingres_"),
    ("Ingres",        'ingres sqlstate',         r"Ingres SQLSTATE"),
    ("Ingres",        'ingres',                  r"Ingres\W.{0,500}?Driver"),
    ("Ingres",        'com.ingres.gcf.jdbc',     r"com\.ingres\.gcf\.jdbc"),
    # ---- FrontBase -----------------------------------------------------
    ("FrontBase",     '. transaction rollback',  r"Exception (condition )?\d+\. Transaction rollback"),
    ("FrontBase",     'com.frontbase.jdbc',      r"com\.frontbase\.jdbc"),
    ("FrontBase",     'syntax error 1',          r"Syntax error 1. Missing"),
    ("FrontBase",     ' error ',                 r"(Semantic|Syntax) error [1-4]\d{2}\."),
    # ---- HSQLDB --------------------------------------------------------
    ("HSQLDB",        'unexpected end of command in statement [', r"Unexpected end of command in statement \["),
    ("HSQLDB",        'unexpected token',        r"Unexpected token.{0,500}?in statement \["),
    ("HSQLDB",        'org.hsqldb.jdbc',         r"org\.hsqldb\.jdbc"),
    # ---- H2 ------------------------------------------------------------
    ("H2",            'org.h2.jdbc',             r"org\.h2\.jdbc"),
    ("H2",            '[42000-192]',             r"\[42000-192\]"),
    # ---- MonetDB -------------------------------------------------------
    ("MonetDB",       '',                        r"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)"),
    ("MonetDB",       '[monetdb][odbc driver',   r"\[MonetDB\]\[ODBC Driver"),
    ("MonetDB",       'nl.cwi.monetdb.jdbc',     r"nl\.cwi\.monetdb\.jdbc"),
    # ---- Derby ---------------------------------------------------------
    ("Derby",         'syntax error: encountered', r"Syntax error: Encountered"),
    ("Derby",         'org.apache.derby',        r"org\.apache\.derby"),
    ("Derby",         'error 42x01',             r"ERROR 42X01"),
    # ---- Vertica -------------------------------------------------------
    ("Vertica",       ', sqlstate: ',            r", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):"),
    ("Vertica",       '/vertica/parser/scan',    r"/vertica/Parser/scan"),
    ("Vertica",       'com.vertica.jdbc',        r"com\.vertica\.jdbc"),
    ("Vertica",       'org.jkiss.dbeaver.ext.vertica', r"org\.jkiss\.dbeaver\.ext\.vertica"),
    ("Vertica",       'com.vertica.dsi.dataengine', r"com\.vertica\.dsi\.dataengine"),
    # ---- Mckoi ---------------------------------------------------------
    ("Mckoi",         'com.mckoi.jdbcdriver',    r"com\.mckoi\.JDBCDriver"),
    ("Mckoi",         'com.mckoi.database.jdbc', r"com\.mckoi\.database\.jdbc"),
    ("Mckoi",         '<regex_literal>',         r"<REGEX_LITERAL>"),
    # ---- Presto --------------------------------------------------------
    ("Presto",        'com.facebook.presto.jdbc', r"com\.facebook\.presto\.jdbc"),
    ("Presto",        'io.prestosql.jdbc',       r"io\.prestosql\.jdbc"),
    ("Presto",        'com.simba.presto.jdbc',   r"com\.simba\.presto\.jdbc"),
    ("Presto",        'union query has different number of fields: ', r"UNION query has different number of fields: \d+, \d+"),
    # ---- Altibase ------------------------------------------------------
    ("Altibase",      'altibase.jdbc.driver',    r"Altibase\.jdbc\.driver"),
    # ---- MimerSQL ------------------------------------------------------
    ("MimerSQL",      'com.mimer.jdbc',          r"com\.mimer\.jdbc"),
    ("MimerSQL",      'assumed to mean',         r"Syntax error,[^\n]+assumed to mean"),
    # ---- CrateDB -------------------------------------------------------
    ("CrateDB",       'io.crate.client.jdbc',    r"io\.crate\.client\.jdbc"),
    # ---- InterSystems Cache --------------------------------------------
    ("InterSystems Cache", 'encountered after end of query', r"encountered after end of query"),
    ("InterSystems Cache", 'a comparison operator is required here', r"A comparison operator is required here"),
    # ---- Raima ---------------------------------------------------------
    ("Raima",         '-10048: syntax error',    r"-10048: Syntax error"),
    ("Raima",         'rdmstmtprepare(',         r"rdmStmtPrepare\(.+?\) returned"),
    # ---- Virtuoso ------------------------------------------------------
    ("Virtuoso",      'sq074: line ',            r"SQ074: Line \d+:"),
    ("Virtuoso",      'sr185: undefined procedure', r"SR185: Undefined procedure"),
    ("Virtuoso",      'sq200: no table ',        r"SQ200: No table "),
    ("Virtuoso",      'virtuoso s0002 error',    r"Virtuoso S0002 Error"),
    ("Virtuoso",      '][virtuoso server]',      r"\[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]"),
    # ---- MySQL ---------------------------------------------------------
    ("MySQL",         'you have an error in your sql syntax', r"You have an error in your SQL syntax"),
    ("MySQL",         'mysql_fetch_',            r"mysql_fetch_(array|assoc|row|object|field|lengths)"),
    ("MySQL",         'supplied argument is not a valid mysql', r"supplied argument is not a valid MySQL"),
    ("MySQL",         'com.mysql.cj.',           r"com\.mysql\.cj\."),
    ("MySQL",         "' doesn't exist",         r"Table '[^']{1,120}' doesn't exist"),
    ("MySQL",         "column count doesn't match value count", r"Column count doesn't match value count"),
    ("MySQL",         'truncated incorrect ',    r"Truncated incorrect \w{1,20} value"),
    ("MySQL",         'incorrect ',              r"Incorrect (integer|string|decimal|column name) value"),
    ("MySQL",         'pymysql.err.',            r"pymysql\.err\.(ProgrammingError|InternalError|OperationalError|DataError)"),
    # ---- MariaDB -------------------------------------------------------
    ("MariaDB",       'mariadb server version for the right syntax', r"MariaDB server version for the right syntax"),
    # ---- PostgreSQL ----------------------------------------------------
    ("PostgreSQL",    'pg::',                    r"PG::(UndefinedColumn|UndefinedTable|DatatypeMismatch|InvalidTextRepresentation|UndefinedFunction)"),
    ("PostgreSQL",    'psycopg',                 r"psycopg2?\.(Error|ProgrammingError|OperationalError|DataError|errors\.\w+)"),
    ("PostgreSQL",    'unterminated quoted ',    r"unterminated quoted (string|identifier) at or near"),
    ("PostgreSQL",    'invalid input syntax for ', r"invalid input syntax for (type )?(integer|bigint|numeric|double precision|boolean|uuid|json)"),
    ("PostgreSQL",    '" does not exist',        r'(column|relation|function) \"[^\"]{1,80}\" does not exist'),
    ("PostgreSQL",    'operator does not exist: ', r"operator does not exist: "),
    ("PostgreSQL",    'pq: syntax error at or near', r"\bpq: syntax error at or near"),
    # ---- MSSQL ---------------------------------------------------------
    ("MSSQL",         'incorrect syntax near',   r"Incorrect syntax near"),
    ("MSSQL",         'microsoft.data.sqlclient.sqlexception', r"Microsoft\.Data\.SqlClient\.SqlException"),
    ("MSSQL",         'conversion failed when converting the ', r"Conversion failed when converting the \w{0,10}char value"),
    ("MSSQL",         'error converting data type ', r"Error converting data type \w+ to \w+"),
    ("MSSQL",         "invalid column name '",   r"Invalid column name '[^']{1,80}'"),
    ("MSSQL",         ', level ',                r"Msg \d{3,5}, Level \d+, State \d+"),
    ("MSSQL",         'mssql: ',                 r"mssql: .{0,60}?syntax"),
    # ---- Oracle --------------------------------------------------------
    ("Oracle",        'pls-',                    r"\bPLS-\d{5}\b"),
    ("Oracle",        'ora-',                    r"\bORA-\d{4}\b"),
    # ---- SQLite --------------------------------------------------------
    ("SQLite",        '[sqlite_error]',          r"\[SQLITE_ERROR\]"),
    ("SQLite",        'sqlite',                  r"sqlite3?\.(ProgrammingError|DatabaseError|IntegrityError|Warning)"),
    ("SQLite",        'unrecognized token: ',    r"unrecognized token: "),
    ("SQLite",        'no such ',                r"no such (table|column|function): "),
    # ---- DB2 -----------------------------------------------------------
    ("DB2",           'sqlcode',                 r"\bSQLCODE[=:\s-]{1,3}-?\d{3,5}"),
    ("DB2",           'sqlstate',                r"\bSQLSTATE[=:\s]{1,3}\d{5}"),
    # ---- H2 ------------------------------------------------------------
    ("H2",            'org.h2.jdbc.jdbcsql',     r"org\.h2\.jdbc\.JdbcSQLE?\w*Exception"),
    ("H2",            'syntax error in sql statement', r"Syntax error in SQL statement"),
    # ---- ClickHouse ----------------------------------------------------
    ("ClickHouse",    'db::exception',           r"DB::Exception"),
    # ---- Snowflake -----------------------------------------------------
    ("Snowflake",     'net.snowflake.client.jdbc.snowflakesqlexception', r"net\.snowflake\.client\.jdbc\.SnowflakeSQLException"),
    # ---- Trino ---------------------------------------------------------
    ("Trino",         'io.trino.',               r"io\.trino\.(sql\.parser\.ParsingException|jdbc)"),
    ("Trino",         'query failed (#',         r"Query failed \(#\w+\)"),
    # ---- Hive ----------------------------------------------------------
    ("Hive",          'org.apache.hive.service.cli.hivesqlexception', r"org\.apache\.hive\.service\.cli\.HiveSQLException"),
    # ---- Impala --------------------------------------------------------
    ("Impala",        'analysisexception: syntax error', r"AnalysisException: Syntax error"),
    # ---- Cassandra -----------------------------------------------------
    ("Cassandra",     'com.datastax.driver.core.exceptions.syntaxerror', r"com\.datastax\.driver\.core\.exceptions\.SyntaxError"),
    # ---- CockroachDB ---------------------------------------------------
    ("CockroachDB",   'cockroachdb',             r"CockroachDB"),
    # ---- PDO -----------------------------------------------------------
    ("PDO",           'uncaught pdoexception',   r"Uncaught PDOException"),
    ("PDO",           'pdoexception',            r"\bPDOException\b"),
    ("PDO",           'sqlstate[',               r"SQLSTATE\[[0-9A-Z]{5}\]"),
    # ---- ODBC ----------------------------------------------------------
    ("ODBC",          'system.data.odbc.odbcexception', r"System\.Data\.Odbc\.OdbcException"),
    # ---- OLE DB --------------------------------------------------------
    ("OLE DB",        'system.data.oledb.oledbexception', r"System\.Data\.OleDb\.OleDbException"),
    # ---- JDBC ----------------------------------------------------------
    ("JDBC",          'java.sql.sql',            r"java\.sql\.SQL(Syntax|Data|Integrity|Feature)?\w*Exception"),
    # ---- Hibernate -----------------------------------------------------
    ("Hibernate",     'org.hibernate.',          r"org\.hibernate\.(exception\.\w+|QueryException|QuerySyntaxException|hql\.internal)"),
    ("Hibernate",     'could not ',              r"could not (prepare statement|extract ResultSet|execute (statement|query))"),
    ("Hibernate",     'jdbcexceptionreporter',   r"JDBCExceptionReporter"),
    # ---- JPA -----------------------------------------------------------
    ("JPA",           'javax.persistence.persistenceexception', r"javax\.persistence\.PersistenceException"),
    # ---- SQLAlchemy ----------------------------------------------------
    ("SQLAlchemy",    'sqlalchemy.exc.',         r"sqlalchemy\.exc\.(ProgrammingError|OperationalError|DataError|StatementError|InternalError)"),
    # ---- Django ORM ----------------------------------------------------
    ("Django ORM",    'django.db.utils.',        r"django\.db\.utils\.(ProgrammingError|OperationalError|DataError|InternalError)"),
    # ---- ActiveRecord --------------------------------------------------
    ("ActiveRecord",  'activerecord::',          r"ActiveRecord::(StatementInvalid|PreparedStatementInvalid)"),
    # ---- Sequelize -----------------------------------------------------
    ("Sequelize",     'sequelize',               r"Sequelize(Database|Connection)Error"),
    # ---- Knex ----------------------------------------------------------
    ("Knex",          'knex: ',                  r"Knex: .{0,40}?(syntax|error)"),
    # ---- GORM ----------------------------------------------------------
    ("GORM",          'gorm: ',                  r"gorm: .{0,60}?syntax"),
    # ---- pyodbc --------------------------------------------------------
    ("pyodbc",        'pyodbc.',                 r"pyodbc\.(Error|ProgrammingError|DataError|OperationalError)"),
    # ---- EF Core -------------------------------------------------------
    ("EF Core",       'microsoft.entityframeworkcore', r"Microsoft\.EntityFrameworkCore.{0,60}?Exception"),
]

GENERIC_ERROR_SIGNATURES = [
    ("Generic",       ' error',                  r"SQL (syntax|statement) error"),
    ("Generic",       'syntax error at line ',   r"syntax error at line \d+"),
    ("Generic",       ' error ',                 r"(parse|parser) error (near|at)"),
    ("Generic",       'unexpected end of ',      r"unexpected end of (SQL |)?(command|statement|input)"),
    ("Generic",       'unterminated ',           r"unterminated (quoted )?string"),
    ("Generic",       'unclosed quotation',      r"unclosed quotation"),
    ("Generic",       'query',                   r"(invalid|malformed|bad) (SQL |)query"),
    ("Generic",       'query ',                  r"query (failed|execution failed)"),
    ("Generic",       'database e',              r"database (error|exception)"),
    ("Generic",       ' error',                  r"(ODBC|JDBC) error"),
]


def _compile_sigs(triples):
    out = []
    for dbms, gate, pat in triples:
        try:
            out.append((dbms, gate, re.compile(pat, re.IGNORECASE)))
        except Exception as ex:
            print("[SQLi Tester v4] bad signature %r: %s" % (pat, ex))
    return out

SQL_ERROR_RE     = _compile_sigs(SQL_ERROR_SIGNATURES)
GENERIC_ERROR_RE = _compile_sigs(GENERIC_ERROR_SIGNATURES)
SQL_GATES        = sorted(set(g for (_d, g, _r) in SQL_ERROR_RE + GENERIC_ERROR_RE if g))

SCAN_LIMIT = 300000      # only the first 300 KB of a response is searched


def sql_error_hits(text, include_generic=False, limit=6):
    """[(engine, matched text)] for every signature that fires in the response."""
    hits = []
    if not text:
        return hits
    body    = text[:SCAN_LIMIT]
    low     = body.lower()
    present = set(g for g in SQL_GATES if g in low)
    seen    = set()
    for dbms, gate, rx in (SQL_ERROR_RE + (GENERIC_ERROR_RE if include_generic else [])):
        if gate and gate not in present:
            continue
        m = rx.search(body)
        if not m:
            continue
        snip = " ".join(m.group(0).split())[:150]
        key  = (dbms, snip.lower())
        if key in seen:
            continue
        seen.add(key)
        hits.append((dbms, snip))
        if len(hits) >= limit:
            break
    return hits


# ---------------------------------------------------------------------------
# Time-based payload helpers.  "+" counts as whitespace throughout, because
# that is how the payloads above are written.
# ---------------------------------------------------------------------------
_SLEEP_RE   = re.compile(r"(?:pg_)?sleep[\s+]*\([\s+]*(\d+(?:\.\d+)?)", re.IGNORECASE)
_RECVMSG_RE = re.compile(r"receive_message[\s+]*\([^,)]*,[\s+]*(\d+)", re.IGNORECASE)
_WAITFOR_RE = re.compile(r"waitfor[\s+]+delay[\s+]+'?[\s+]*(\d+)[\s+]*:[\s+]*(\d+)"
                         r"[\s+]*:[\s+]*(\d+(?:\.\d+)?)", re.IGNORECASE)
_WAITFOR_ANY = re.compile(r"waitfor[\s+]+delay", re.IGNORECASE)
_HEAVY_RE   = re.compile(r"benchmark[\s+]*\(|randomblob[\s+]*\(|generate_series[\s+]*\(|"
                         r"sysusers[\s+]+as|rlike[\s+]*\([\s+]*select|repeat[\s+]*\([\s+]*0x",
                         re.IGNORECASE)


def payload_sleep_secs(payload, default_secs):
    """How long this payload should stall the response, or None if it is not
    a time-based payload at all."""
    if not payload:
        return None
    m = _SLEEP_RE.search(payload)
    if m:
        return float(m.group(1))
    m = _RECVMSG_RE.search(payload)
    if m:
        return float(m.group(1))
    m = _WAITFOR_RE.search(payload)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))
    if _WAITFOR_ANY.search(payload) or _HEAVY_RE.search(payload):
        return float(default_secs)   # no literal duration - assume the configured one
    return None


def retime_payload(payload, secs):
    """Same payload with its delay rewritten to `secs`.  None if there is no
    adjustable delay in it (BENCHMARK / RANDOMBLOB etc.)."""
    p = _SLEEP_RE.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + str(int(secs)), payload)
    p = re.sub(r"(receive_message[\s+]*\([^,)]*,[\s+]*)\d+", r"\g<1>%d" % secs, p,
               flags=re.IGNORECASE)
    p = re.sub(r"(delay[\s+]+'?[\s+]*\d+[\s+]*:[\s+]*\d+[\s+]*:[\s+]*)\d+", r"\g<1>%02d" % secs,
               p, flags=re.IGNORECASE)
    return p if p != payload else None


def safe_value(value):
    """Payloads go in raw - no percent-encoding.  Only the characters that
    would end the parameter early are neutralised, plus CR/LF."""
    return (value.replace("\r", "").replace("\n", "")
                 .replace("&", "%26").replace("#", "%23"))


def safe_cookie_value(value):
    """Same, plus the characters that would start a new cookie."""
    return (safe_value(value).replace(";", "%3B").replace(",", "%2C")
                             .replace(" ", "%20"))


# ---------------------------------------------------------------------------
# Widget helpers
# ---------------------------------------------------------------------------
def fmt(v):
    return str(v) if v else ""

def mk_lbl(text, size=12, bold=False, color=None):
    l = JLabel(text)
    l.setForeground(color if color else FG)
    l.setFont(Font("Segoe UI", Font.BOLD if bold else Font.PLAIN, size))
    return l

def mk_btn(text, bg=ACCENT, fg=Color.WHITE):
    b = JButton(text)
    b.setBackground(bg); b.setForeground(fg)
    b.setFocusPainted(False); b.setBorderPainted(False)
    b.setFont(Font("Segoe UI", Font.BOLD, 12))
    return b

def mk_field(text="", w=10):
    f = JTextField(text, w)
    f.setBackground(BG3); f.setForeground(FG); f.setCaretColor(FG)
    f.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(BORDER),
        BorderFactory.createEmptyBorder(3, 6, 3, 6)))
    f.setFont(Font("Courier New", Font.PLAIN, 12))
    return f

def mk_area(editable=True):
    a = JTextArea()
    a.setBackground(BG2); a.setForeground(FG)
    a.setCaretColor(FG); a.setEditable(editable)
    a.setFont(Font("Courier New", Font.PLAIN, 12))
    return a

def mk_radio(text, sel=False):
    r = JRadioButton(text, sel)
    r.setBackground(BG); r.setForeground(FG)
    r.setFont(Font("Segoe UI", Font.PLAIN, 12))
    r.setFocusPainted(False)
    return r

def mk_card(title, inner):
    p = JPanel(BorderLayout())
    p.setBackground(BG2)
    p.setBorder(BorderFactory.createTitledBorder(
        BorderFactory.createLineBorder(BORDER), title,
        0, 0, Font("Segoe UI", Font.BOLD, 11), FG_DIM))
    sc = JScrollPane(inner)
    sc.getViewport().setBackground(BG2); sc.setBorder(None)
    p.add(sc)
    return p

def style_table(t):
    t.setBackground(BG2); t.setForeground(FG)
    t.setGridColor(BORDER); t.setRowHeight(22)
    t.setFont(Font("Courier New", Font.PLAIN, 11))
    t.getTableHeader().setBackground(BG3)
    t.getTableHeader().setForeground(FG)
    t.getTableHeader().setFont(Font("Segoe UI", Font.BOLD, 11))
    t.setSelectionBackground(ACCENT); t.setSelectionForeground(Color.WHITE)
    t.setShowHorizontalLines(True); t.setShowVerticalLines(False)

# ---------------------------------------------------------------------------
# Pretty printing (JSON / XML body of an HTTP message)
# ---------------------------------------------------------------------------
def pretty_message(raw):
    if not raw:
        return raw
    sep = "\r\n\r\n"; idx = raw.find(sep)
    if idx < 0:
        sep = "\n\n"; idx = raw.find(sep)
    if idx < 0:
        return raw
    return raw[:idx] + sep + _pretty_body(raw[idx + len(sep):])

def _pretty_body(body):
    b = body.strip()
    if not b:
        return body
    if b[0] in "{[":
        try:
            import json
            return json.dumps(json.loads(b), indent=2)
        except Exception:
            return body
    if b[0] == "<":
        try:
            return _pretty_xml(b)
        except Exception:
            return body
    return body

def _pretty_xml(x):
    import re
    x = re.sub(r">\s*<", ">\n<", x.strip())
    out, indent = [], 0
    for line in x.split("\n"):
        line = line.strip()
        if not line:
            continue
        if re.match(r"^</", line):
            indent = max(0, indent - 1)
        out.append("  " * indent + line)
        if re.match(r"^<[^/!?]", line) and not line.endswith("/>") and "</" not in line:
            indent += 1
    return "\n".join(out)

# ---------------------------------------------------------------------------
# Searchable message view — pretty toggle + Repeater-style < > navigation
# ---------------------------------------------------------------------------
class _MVSearchDoc(DocumentListener):
    def __init__(self, mv):
        self._mv = mv
    def insertUpdate(self, e):  self._mv.search()
    def removeUpdate(self, e):  self._mv.search()
    def changedUpdate(self, e): self._mv.search()

class MessageView(JPanel):
    def __init__(self, title):
        JPanel.__init__(self, BorderLayout())
        self.setBackground(BG2)
        self.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(BORDER), title,
            0, 0, Font("Segoe UI", Font.BOLD, 11), FG_DIM))
        self._raw     = ""
        self._matches = []
        self._cur     = -1

        self.area = JTextArea()
        self.area.setBackground(BG2); self.area.setForeground(FG)
        self.area.setCaretColor(FG); self.area.setEditable(False)
        self.area.setFont(Font("Courier New", Font.PLAIN, 12))
        self.area.setSelectionColor(ACCENT)
        self.area.setSelectedTextColor(Color.WHITE)
        self._painter = DefaultHighlighter.DefaultHighlightPainter(Color(120, 100, 40))

        sc = JScrollPane(self.area)
        sc.getViewport().setBackground(BG2); sc.setBorder(None)
        self.add(sc, BorderLayout.CENTER)
        self.add(self._bar(), BorderLayout.SOUTH)

    def _bar(self):
        bar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        bar.setBackground(BG3)
        bar.add(mk_lbl("Find:", 11))
        self._sf = JTextField("", 16)
        self._sf.setBackground(BG2); self._sf.setForeground(FG); self._sf.setCaretColor(FG)
        self._sf.setFont(Font("Courier New", Font.PLAIN, 12))
        self._sf.getDocument().addDocumentListener(_MVSearchDoc(self))
        self._sf.addActionListener(lambda e: self.find_next())
        bar.add(self._sf)
        bp = mk_btn("  <  ", BG2, FG); bp.addActionListener(lambda e: self.find_prev())
        bn = mk_btn("  >  ", BG2, FG); bn.addActionListener(lambda e: self.find_next())
        bar.add(bp); bar.add(bn)
        self._count = mk_lbl("0/0", 11, color=FG_DIM)
        bar.add(self._count)
        self._pretty = JCheckBox("Pretty", True)
        self._pretty.setBackground(BG3); self._pretty.setForeground(FG)
        self._pretty.addActionListener(lambda e: self._render())
        bar.add(self._pretty)
        return bar

    def set_text(self, raw):
        self._raw = raw or ""
        self._render()

    def _render(self):
        txt = pretty_message(self._raw) if self._pretty.isSelected() else self._raw
        self.area.setText(txt)
        self.area.setCaretPosition(0)
        self.search()

    def search(self):
        self.area.getHighlighter().removeAllHighlights()
        self._matches = []; self._cur = -1
        q = self._sf.getText()
        if q:
            text = self.area.getText().lower(); needle = q.lower()
            start = 0
            while True:
                i = text.find(needle, start)
                if i < 0:
                    break
                self._matches.append(i)
                try:
                    self.area.getHighlighter().addHighlight(i, i + len(q), self._painter)
                except Exception:
                    pass
                start = i + len(q)
            if self._matches:
                self._cur = 0
                self._focus()
        self._update()

    def find_next(self):
        if self._matches:
            self._cur = (self._cur + 1) % len(self._matches)
            self._focus()

    def find_prev(self):
        if self._matches:
            self._cur = (self._cur - 1) % len(self._matches)
            self._focus()

    def _focus(self):
        i = self._matches[self._cur]; q = self._sf.getText()
        self.area.select(i, i + len(q))
        try:
            r = self.area.modelToView(i)
            if r:
                self.area.scrollRectToVisible(r)
        except Exception:
            pass
        self._update()

    def _update(self):
        n = len(self._matches)
        self._count.setText(("%d/%d" % (self._cur + 1, n)) if n else "0/0")

# ---------------------------------------------------------------------------
# Table models
# ---------------------------------------------------------------------------
class QueueModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, ["#", "Method", "Host", "Path", "Params"], 0)
    def isCellEditable(self, r, c): return False

class ResultModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Request", "Parameter", "Where", "Payload", "Mode",
             "Status", "Length", "Time(ms)", "SQL Err", "DBMS", "Flags"], 0)
    def isCellEditable(self, r, c): return False

# Columns that must sort numerically (#, Status, Length, Time, error count)
NUMERIC_COLS = (0, 6, 7, 8, 9)
RES_FLAGS_COL = 11

class NumComparator(Comparator):
    def compare(self, a, b):
        return cmp(self._f(a), self._f(b))
    def _f(self, v):
        try:
            return float(str(v).strip())
        except Exception:
            return float("-inf")   # blanks / non-numeric sort below any number

class FindingsModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self,
            ["#", "Type", "Severity", "Request", "Parameter", "Where",
             "Payload", "Hits", "Evidence"], 0)
    def isCellEditable(self, r, c): return False

class FindingsRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr  = table.convertRowIndexToModel(row)
        sev = str(table.getModel().getValueAt(mr, 2) or "")
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif sev == "High":
            c.setBackground(Color(70, 35, 35)); c.setForeground(Color(255, 120, 120))
        elif sev == "Medium":
            c.setBackground(Color(70, 60, 30)); c.setForeground(YELLOW)
        elif sev == "Low":
            c.setBackground(Color(38, 48, 58)); c.setForeground(Color(150, 185, 215))
        else:
            c.setBackground(BG2); c.setForeground(FG)
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))   # full text on hover (esp. Evidence)
        except Exception:
            pass
        return c

# ---------------------------------------------------------------------------
# Cell renderer — highlights rows with findings
# ---------------------------------------------------------------------------
class FindingRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, foc, row, col)
        mr    = table.convertRowIndexToModel(row)
        flags = str(table.getModel().getValueAt(mr, RES_FLAGS_COL) or "")
        if sel:
            c.setBackground(ACCENT); c.setForeground(Color.WHITE)
        elif "SQLERR" in flags or "5" == flags[:1] or "NO-RESP" in flags:
            c.setBackground(Color(70, 35, 35)); c.setForeground(Color(255, 120, 120))
        elif "SLOW" in flags:
            c.setBackground(Color(70, 60, 30)); c.setForeground(YELLOW)
        elif flags.strip():
            c.setBackground(Color(60, 40, 40)); c.setForeground(YELLOW)
        else:
            c.setBackground(BG2); c.setForeground(FG)
        c.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        try:
            c.setToolTipText(str(value))
        except Exception:
            pass
        return c

# ---------------------------------------------------------------------------
# Listeners
# ---------------------------------------------------------------------------
class QueueSel(ListSelectionListener):
    def __init__(self, ext):
        self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._q_table.getSelectedRow()
            if r >= 0:
                self._e._show_queue_detail(r)

class ResultRowSel(ListSelectionListener):
    def __init__(self, ext):
        self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._res_table.getSelectedRow()
            if r >= 0:
                self._e._show_pair(r)

class FindingRowSel(ListSelectionListener):
    def __init__(self, ext):
        self._e = ext
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            r = self._e._f_table.getSelectedRow()
            if r >= 0:
                self._e._show_finding_pair(r)

# ---------------------------------------------------------------------------
# Site map import
#
# Right-clicking a host in the Site map tree and picking the recursive item
# pulls every request Burp has already recorded for that host into the queue,
# instead of having to expand the tree and shift-select requests by hand.
#
# A Site map tree selection hands back one entry per selected node. That entry
# has a URL but usually no request bytes, so its URL has to be read with
# getUrl() - analyzeRequest() has nothing to work with and comes back empty,
# which is what made an earlier attempt at this silently find no hosts. The
# node's own URL is then the prefix for getSiteMap(), which returns the whole
# subtree: the host for a host node, the folder for a folder node. Default
# ports are stripped first, because Burp renders site map URLs without them and
# older builds will not match a prefix that spells one out. This is the same
# route GAP takes, and it is the one that works.
# ---------------------------------------------------------------------------
MAX_IMPORT = 5000       # per invocation; a stop so one host cannot hang Burp
CTX_SITE_MAP_TREE = 4   # IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE

# Skipped on import when the URL carries no parameters at all - a static file
# with nothing to inject into is just wasted requests. A parameterised one
# (/thumb.png?src=...) is kept whatever its extension says.
STATIC_EXT = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".tiff", ".webp", ".avif", ".svg", ".ico", ".cur", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".m4a", ".webm", ".ogg", ".wav",
    ".avi", ".mov", ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".tar", ".exe", ".dmg", ".msi", ".apk", ".dll", ".class", ".jar",
)


def strip_default_port(u):
    """Burp renders site map URLs without the default port, and older builds'
    getSiteMap() will not match a prefix that spells it out - which is why a
    prefix built from analyzeRequest().getUrl() can come back with nothing."""
    for scheme, port in (("https://", ":443"), ("http://", ":80")):
        if u[:len(scheme)].lower() == scheme:
            rest = u[len(scheme):]
            slash = rest.find("/")
            auth = rest if slash < 0 else rest[:slash]
            tail = "" if slash < 0 else rest[slash:]
            if auth.endswith(port):
                auth = auth[:-len(port)]
            return scheme + auth + tail
    return u


def url_authority(u):
    i = u.find("://")
    if i < 0:
        return ""
    rest = u[i + 3:]
    j = rest.find("/")
    return (rest if j < 0 else rest[:j]).lower()


def find_jtree(comp, depth=0):
    """The JTree at or under comp."""
    if comp is None or depth > 6:
        return None
    if isinstance(comp, JTree):
        return comp
    try:
        kids = comp.getComponents()
    except Exception:
        return None
    for ch in kids:
        t = find_jtree(ch, depth + 1)
        if t is not None:
            return t
    return None


def jtree_from_event(ev):
    """The site map tree behind a context menu invocation.

    Burp gives extensions no way to ask what is selected in the Site map tree -
    getSelectedMessages() comes back empty for a host or folder node, which is
    exactly the case worth having. What it does give is the input event the
    menu came from, and for a click in the tree that event belongs to the
    JTree itself (or to something inside it), so the selection can be read off
    the component directly."""
    if ev is None:
        return None
    comp = None
    try:
        comp = ev.getComponent()
    except Exception:
        pass
    if comp is None:
        try:
            comp = ev.getSource()
        except Exception:
            return None
    c = comp
    for _ in range(8):
        if c is None:
            break
        if isinstance(c, JTree):
            return c
        try:
            c = c.getParent()
        except Exception:
            break
    return find_jtree(comp)


def node_label(node):
    try:
        return node.toString() or ""
    except Exception:
        try:
            return str(node)
        except Exception:
            return ""


HOSTISH_RE = re.compile(r"^[A-Za-z0-9._-]+(:\d+)?$")


def tree_selection_labels(tree):
    """The node labels of every selected branch, root first."""
    out = []
    try:
        paths = tree.getSelectionPaths()
    except Exception:
        return out
    for tp in (paths or []):
        try:
            out.append([node_label(n) for n in tp.getPath()])
        except Exception:
            continue
    return out


def tree_prefixes(tree):
    """A getSiteMap() prefix for every selected branch of the Site map tree.

    The node labels rebuild the URL: the host node renders as
    "https://example.com[:port]" and each child is one path segment, so a host
    selection gives "https://example.com/" and a folder selection gives
    "https://example.com/api/". Only the trailing-slash form is used - trimming
    it would turn "https://example.com" into a prefix that also matches
    example.com.evil.net, and "/api" into one that also matches /apiv2."""
    out = []
    for labels in tree_selection_labels(tree):
        pref = None
        for i in range(len(labels)):
            lbl = (labels[i] or "").strip()
            if "://" in lbl:
                rest = [x.strip("/") for x in labels[i + 1:] if (x or "").strip("/")]
                pref = lbl.rstrip("/")
                if rest:
                    pref += "/" + "/".join(rest)
                break
        if pref:
            if not pref.endswith("/"):
                pref += "/"
            if pref not in out:
                out.append(pref)
            continue
        # Some builds label the host node without the scheme. Both schemes are
        # tried; the wrong one simply matches nothing in the site map.
        rest = [(x or "").strip("/") for x in labels[1:]]
        rest = [x for x in rest if x]
        if not rest or not HOSTISH_RE.match(rest[0]):
            continue
        tail = ("/" + "/".join(rest[1:])) if len(rest) > 1 else ""
        for sch in ("https://", "http://"):
            p = sch + rest[0] + tail
            if not p.endswith("/"):
                p += "/"
            if p not in out:
                out.append(p)
    return out


def drop_nested(prefixes):
    """Keep the broadest of any overlapping prefixes - scanning both
    https://x/ and https://x/api/ is the same work twice."""
    out = []
    for p in prefixes:
        if any(p != q and p.startswith(q) for q in prefixes):
            continue
        if p not in out:
            out.append(p)
    return out


def url_host_root(url_str):
    """https://x.com:8443/a/b?q=1  ->  https://x.com:8443/"""
    i = url_str.find("://")
    if i < 0:
        return url_str
    j = url_str.find("/", i + 3)
    return url_str if j < 0 else url_str[:j + 1]


def is_static_url(url_str, has_body):
    """A static asset with no parameters of any kind."""
    if "?" in url_str or has_body:
        return False
    base = url_str.split("#", 1)[0].lower()
    for ext in STATIC_EXT:
        if base.endswith(ext):
            return True
    return False


class DrainTick(ActionListener):
    """Fires on the EDT every DRAIN_MS and flushes whatever the worker threads
    have queued up."""
    def __init__(self, ext):
        self._e = ext
    def actionPerformed(self, e):
        try:
            self._e._drain()
        except Exception as ex:
            print("[SQLi Tester v4] drain error: %s" % ex)


class SearchDoc(DocumentListener):
    def __init__(self, ext):
        self._e = ext
    def insertUpdate(self, e):  self._e._filter()
    def removeUpdate(self, e):  self._e._filter()
    def changedUpdate(self, e): self._e._filter()

# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb     = callbacks
        self._h      = callbacks.getHelpers()
        self._scan   = False
        self._stored = {}
        self._rows   = []
        self._queue  = []   # list of dicts: {req, svc, method, host, path, params}
        # Findings state
        self._findings = []
        self._f_stored = {}
        self._fseen    = {}   # dedup key -> finding id
        self._fhits    = {}   # finding id -> times the same signal fired
        self._confirming = set()   # time hits being re-tested right now
        self._baseline = {}   # id(entry) -> baseline (status / latency / errors)
        # v3 display pipeline.  Worker threads never touch Swing: they drop
        # rows and findings updates in here and one timer on the EDT drains the
        # lot every DRAIN_MS.  v2 posted an invokeLater per request, and with
        # 50 threads that is thousands of events, each one re-sorting the table
        # and walking the findings model - which is what made the table crawl
        # and left the row count disagreeing with the counter.
        # Scan counters live here and not only in the worker: the progress text
        # and the search filter read them, and before the first scan of a
        # session there would be nothing to read.
        self._work         = []
        self._widx         = 0
        self._done         = 0
        self._total        = 0
        self._pending      = []   # rows waiting to be shown
        self._pend_hits    = {}   # finding id -> latest hit count
        self._pend_cells   = {}   # finding id -> (severity, evidence)
        self._pend_frows   = []   # new finding rows
        self._frow_of      = {}   # finding id -> findings-model row index
        self._timer        = None
        self._query        = ""   # the search box, as the drainer sees it
        self._sent         = 0    # every HTTP request actually sent
        self._skipped      = 0    # probes not run because Stop was pressed
        self._bl_probes = 2   # unmodified requests per endpoint; 1 when no
                              # payload in the run can use the latency figure
        self._lock     = threading.Lock()
        self._cnt_lock = threading.Lock()   # requests-sent counter only
        self._quiet    = False   # suppress the per-request console line on bulk import
        self._bl_lock  = threading.Lock()
        self._kept     = 0      # bytes of response text held for the viewer
        self._keep_all = False
        # Detection options (re-read from Settings at the start of every scan)
        self._sleep_secs  = float(SLEEP_SECS)
        self._time_pct    = 60.0
        self._opt_sqlerr  = True
        self._opt_generic = False
        self._opt_http5xx = True
        self._opt_time    = True
        self._opt_confirm = True
        self._opt_status  = False
        # Global rate limiter
        self._rl_lock     = threading.Lock()
        self._rl_next     = 0.0
        self._rl_interval = 1.0 / RPS_CAP

        callbacks.setExtensionName("SQLi Tester v4")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        if SwingUtilities.isEventDispatchThread():
            self._build()
        else:
            SwingUtilities.invokeAndWait(lambda: self._build())

        print("[SQLi Tester v4] Loaded successfully.")

    # -----------------------------------------------------------------------
    # Build UI
    # -----------------------------------------------------------------------
    def _build(self):
        self._root = JPanel(BorderLayout())
        self._root.setBackground(BG)
        self._tabs = JTabbedPane()
        self._tabs.setBackground(BG); self._tabs.setForeground(FG)
        self._tabs.setFont(Font("Segoe UI", Font.BOLD, 12))
        self._tabs.addTab("  Scanner  ",  self._build_scanner())
        self._tabs.addTab("  Results  ",  self._build_results())
        self._tabs.addTab("  Findings  ", self._build_findings())
        self._findings_tab_index = 2
        self._tabs.addTab("  Settings  ", self._build_settings())
        self._root.add(self._tabs)
        self._load_settings()
        self._cb.addSuiteTab(self)

    # -----------------------------------------------------------------------
    # Request parsing + injection — done manually, no dependency on Burp's
    # IParameter objects (which vary between Burp API versions).
    # -----------------------------------------------------------------------
    SKIP_HEADERS = ("host", "content-length", "connection", "accept-encoding",
                    "transfer-encoding", "content-type")

    def _split_req(self, raw):
        head, sep, body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        return lines[0], lines[1:], body, (sep if sep else "\r\n\r\n")

    def _join_req(self, request_line, header_lines, body, sep):
        head = "\r\n".join([request_line] + header_lines)
        return head + sep + body

    def _parse_pairs(self, qs):
        pairs = []
        if qs:
            for part in qs.split("&"):
                k, eq, v = part.partition("=")
                pairs.append([k, v, bool(eq)])
        return pairs

    def _rebuild_qs(self, pairs):
        return "&".join(k + ("=" + v if eq else "") for (k, v, eq) in pairs)

    def _set_pair(self, pairs, name, new_value):
        done = False
        for pair in pairs:
            if pair[0] == name and not done:
                pair[1] = new_value; pair[2] = True; done = True
        return pairs

    def _content_type(self, header_lines):
        for hl in header_lines:
            if hl.lower().startswith("content-type:"):
                return hl.split(":", 1)[1].strip().lower()
        return ""

    def _parse_json_points(self, body):
        try:
            import json
            data = json.loads(body)
        except Exception as ex:
            print("[SQLi Tester v4] JSON parse failed, regex fallback: %s" % ex)
            return self._json_regex(body)

        pts, seen = [], set()

        def leaf_name(path):
            # the real key name: last non-numeric path segment
            for seg in reversed(path):
                if not seg.isdigit():
                    return seg
            return path[-1] if path else "json"

        def norm(path):
            # array indices collapsed so reqs.0.x, reqs.1.x ... count once
            return ".".join("[]" if seg.isdigit() else seg for seg in path)

        def walk(obj, path):
            if isinstance(obj, dict):
                for k in obj:
                    walk(obj[k], path + [str(k)])
            elif isinstance(obj, list):
                for i in range(len(obj)):
                    walk(obj[i], path + [str(i)])
            else:
                nkey = norm(path)
                if nkey in seen:
                    return
                seen.add(nkey)
                pts.append({"kind": "json", "name": leaf_name(path), "path": path,
                            "value": "" if obj is None else str(obj), "sig": "json:" + nkey})
        walk(data, [])
        return pts

    def _json_regex(self, body):
        import re
        pts, seen = [], set()
        for m in re.finditer(r'"([^"]+)"\s*:\s*(?:"([^"]*)"|([-0-9.]+)|true|false|null)', body):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
            pts.append({"kind": "json", "name": name, "path": [name],
                        "value": val, "sig": "json:" + name})
        return pts

    def _scope(self):
        """Which classes of parameter the user wants scanned."""
        return {"url":    self._ck_url.isSelected(),
                "body":   self._ck_body.isSelected(),
                "header": self._ck_headers.isSelected(),
                "cookie": self._ck_cookies.isSelected()}

    def _parse_points(self, raw, scope):
        """Return list of injection-point dicts parsed straight from the raw
        request, limited to the parameter classes turned on in `scope`."""
        items = []
        request_line, header_lines, body, sep = self._split_req(raw)
        parts  = request_line.split(" ")
        target = parts[1] if len(parts) > 1 else "/"
        _, q, query = target.partition("?")

        # URL query params  (the "GET" box - present on POSTs too)
        if scope.get("url"):
            for (k, v, eq) in self._parse_pairs(query):
                if k:
                    items.append({"kind": "url", "name": k, "value": v})

        # Body params  (the "POST" box - form-encoded or JSON)
        ct = self._content_type(header_lines)
        bstr = body.strip()
        if scope.get("body") and bstr:
            if "json" in ct or (bstr[:1] in ("{", "[") and "=" not in bstr.split("\n", 1)[0]):
                items += self._parse_json_points(bstr)
            else:
                for (k, v, eq) in self._parse_pairs(bstr):
                    if k:
                        items.append({"kind": "body", "name": k, "value": v})

        # Cookies
        if scope.get("cookie"):
            for hl in header_lines:
                if hl.lower().startswith("cookie:"):
                    for c in hl.split(":", 1)[1].split(";"):
                        k, eq, v = c.strip().partition("=")
                        if k:
                            items.append({"kind": "cookie", "name": k, "value": v})

        # Headers
        if scope.get("header"):
            for hl in header_lines:
                if ":" not in hl:
                    continue
                name = hl.split(":", 1)[0].strip()
                if name.lower() in self.SKIP_HEADERS or name.lower() == "cookie":
                    continue
                items.append({"kind": "header", "name": name,
                              "value": hl.split(":", 1)[1].strip()})

        # Dedup — JSON uses its normalized-path sig; others use kind:name
        seen, out = set(), []
        for it in items:
            key = it.get("sig") or (it["kind"] + ":" + it["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    def _set_json(self, body, path, new_value):
        try:
            import json
            data = json.loads(body)
            ref = data
            for key in path[:-1]:
                ref = ref[int(key)] if isinstance(ref, list) else ref[key]
            last = path[-1]
            if isinstance(ref, list):
                ref[int(last)] = new_value
            else:
                ref[last] = new_value
            return json.dumps(data)
        except Exception as ex:
            print("[SQLi Tester v4] JSON set failed: %s" % ex)
            return body

    def _fix_content_length(self, request_line, header_lines, body, sep):
        blen = len(self._h.stringToBytes(body)) if body else 0
        out = []
        for hl in header_lines:
            if hl.lower().startswith("content-length:"):
                out.append("Content-Length: %d" % blen)
            else:
                out.append(hl)
        return out

    def _plus_space(self, value):
        """A "+" in a payload stands for a space.  URL query strings, form
        bodies and most cookie parsers turn it back into one; nothing does
        that for a JSON string, so substitute it here instead."""
        try:
            if not self._ck_plus.isSelected():
                return value
        except Exception:
            pass
        return value.replace("+", " ")

    def _inject(self, raw, item, new_value):
        """Return modified request bytes with new_value placed at the injection point."""
        request_line, header_lines, body, sep = self._split_req(raw)
        kind = item["kind"]

        if kind == "url":
            parts = request_line.split(" ")
            path, q, query = parts[1].partition("?")
            pairs = self._set_pair(self._parse_pairs(query), item["name"],
                                   safe_value(new_value))
            parts[1] = path + ("?" + self._rebuild_qs(pairs) if pairs else "")
            request_line = " ".join(parts)
        elif kind == "body":
            pairs = self._set_pair(self._parse_pairs(body.strip()), item["name"],
                                   safe_value(new_value))
            body = self._rebuild_qs(pairs)
        elif kind == "json":
            body = self._set_json(body, item.get("path", [item["name"]]),
                                  self._plus_space(new_value))
        elif kind == "cookie":
            cval = safe_cookie_value(new_value)
            out = []
            for hl in header_lines:
                if hl.lower().startswith("cookie:"):
                    cs, done = [], False
                    for c in hl.split(":", 1)[1].split(";"):
                        k, eq, v = c.strip().partition("=")
                        if k == item["name"] and not done:
                            cs.append("%s=%s" % (k, cval)); done = True
                        else:
                            cs.append(c.strip())
                    out.append("Cookie: " + "; ".join(cs))
                else:
                    out.append(hl)
            header_lines = out
        elif kind == "header":
            hval = new_value.replace("\r", "").replace("\n", "")
            nl = item["name"].lower()
            header_lines = ["%s: %s" % (item["name"], hval)
                            if (":" in hl and hl.split(":", 1)[0].strip().lower() == nl) else hl
                            for hl in header_lines]

        header_lines = self._fix_content_length(request_line, header_lines, body, sep)
        return self._h.stringToBytes(self._join_req(request_line, header_lines, body, sep))

    def _endpoint_sig(self, entry, surface_only=True):
        """What counts as "already queued".

        surface_only collapses requests that differ only in parameter values,
        because injecting into the same parameter is the same test either way.
        Otherwise only a byte-identical request counts as a duplicate, so a
        host import queues everything the host actually has."""
        if not surface_only:
            return entry["raw"]
        items = sorted((it.get("sig") or (it["kind"] + ":" + it["name"])) for it in entry["params"])
        return "%s %s %s [%s]" % (entry["method"], entry["host"], entry["path"], ",".join(items))

    def _load_one(self, msg, scope):
        req_bytes = msg.getRequest()
        service   = msg.getHttpService()
        if req_bytes is None or service is None:
            if not self._quiet:
                print("[SQLi Tester v4] skip: null request/service")
            return None
        try:
            raw = self._h.bytesToString(req_bytes)
        except Exception as ex:
            print("[SQLi Tester v4] bytesToString failed: %s" % ex)
            return None

        request_line, header_lines, body, sep = self._split_req(raw)
        parts  = request_line.split(" ")
        method = parts[0] if parts else "?"
        target = parts[1] if len(parts) > 1 else "/"
        path   = target.split("?", 1)[0]
        try:
            host = str(service.getHost())
        except Exception:
            host = "?"

        items = self._parse_points(raw, scope)
        if not self._quiet:
            print("[SQLi Tester v4] parsed %s %s -> %d injection point(s)  ct=%s"
                  % (method, path, len(items), self._content_type(header_lines)))
        return {"req": req_bytes, "raw": raw, "svc": service, "method": method,
                "host": host, "path": path, "params": items}

    # -----------------------------------------------------------------------
    # Scanner tab
    # -----------------------------------------------------------------------
    def _build_scanner(self):
        p = JPanel(BorderLayout(6, 6))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        self._status_lbl = mk_lbl(
            "Highlight request(s) in Site map / Proxy  >  right-click  >  Send to SQLi Tester v4",
            11, color=FG_DIM)
        sh = JPanel(FlowLayout(FlowLayout.LEFT, 0, 2))
        sh.setBackground(BG); sh.add(self._status_lbl)
        p.add(sh, BorderLayout.NORTH)

        # Queue table (left)
        self._q_model = QueueModel()
        self._q_table = JTable(self._q_model)
        style_table(self._q_table)
        self._q_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        for i, w in enumerate([30, 54, 150, 220, 54]):
            self._q_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._q_table.getSelectionModel().addListSelectionListener(QueueSel(self))

        q_btns = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        q_btns.setBackground(BG2)
        b_rem  = mk_btn("Remove", BG3, FG)
        b_clrq = mk_btn("Clear All", BG3, FG)
        b_rem.addActionListener(lambda e: self._remove_queued())
        b_clrq.addActionListener(lambda e: self._clear_queue())
        b_sort = mk_btn("Sort by params", ACCENT)
        b_sort.setToolTipText(
            "Reorder the queue so the endpoints with the most injection points "
            "come first, and the ones with none sink to the bottom. The scan "
            "runs top to bottom, so after a big site map import this puts the "
            "requests worth testing in front of the filler.")
        b_sort.addActionListener(lambda e: self._sort_queue_params())
        b_dedup = mk_btn("De-duplicate", ACCENT)
        b_dedup.setToolTipText(
            "Collapse requests that share an injection surface - same method, "
            "path and parameter names - keeping the first of each. /s?q=1 and "
            "/s?q=2 become one entry, because injecting into q is the same "
            "test either way.")
        b_dedup.addActionListener(lambda e: self._dedupe_queue())
        b_noparam = mk_btn("Drop 0-param", BG3, FG)
        b_noparam.setToolTipText(
            "Remove every queued request with nothing in the ticked scope to "
            "inject into. They contribute no probes anyway - this just gets "
            "them out of the list.")
        b_noparam.addActionListener(lambda e: self._drop_noparam())
        q_btns.add(b_rem); q_btns.add(b_clrq)
        q_btns.add(b_sort); q_btns.add(b_dedup); q_btns.add(b_noparam)

        q_wrap = JPanel(BorderLayout())
        q_wrap.setBackground(BG)
        q_wrap.add(mk_card("Loaded Requests  (scanned top to bottom)", self._q_table), BorderLayout.CENTER)
        q_wrap.add(q_btns, BorderLayout.SOUTH)

        # Detail (right): params on top, raw request below
        self._detail_params = mk_area(False)
        self._detail_raw    = mk_area(False)
        detail_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                  mk_card("Parameters to test", self._detail_params),
                                  mk_card("Raw Request", self._detail_raw))
        detail_split.setResizeWeight(0.4); detail_split.setDividerSize(4); detail_split.setBackground(BG)

        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, q_wrap, detail_split)
        top_split.setResizeWeight(0.52); top_split.setDividerSize(5); top_split.setBackground(BG)

        # Payloads
        self._payload_area = mk_area()
        self._payload_area.setText("\n".join(DEFAULT_PAYLOADS))

        mid = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split,
                         mk_card("Payloads  (one per line - leading spaces are kept)",
                                 self._payload_area))
        mid.setResizeWeight(0.72); mid.setDividerSize(5); mid.setBackground(BG)
        p.add(mid, BorderLayout.CENTER)

        # Controls - two rows, because one FlowLayout in BorderLayout.SOUTH
        # reports a single row's height and clips whatever does not fit.
        def row():
            r = JPanel(FlowLayout(FlowLayout.LEFT, 10, 3))
            r.setBackground(BG)
            return r

        r1, r2 = row(), row()

        r1.add(mk_lbl("Scan:", 12, True))

        def scope_box(text, sel, tip):
            cb = JCheckBox(text, sel)
            cb.setBackground(BG); cb.setForeground(FG)
            cb.setToolTipText(tip)
            cb.addActionListener(lambda e: self._recount_params())
            r1.add(cb)
            return cb

        self._ck_url = scope_box("GET", True,
            "URL query string parameters - present on POST requests too.")
        self._ck_body = scope_box("POST", True,
            "Request body parameters: form-encoded fields and JSON values.")
        self._ck_headers = scope_box("Headers", False,
            "Every header except Host, Content-Length, Connection, "
            "Accept-Encoding, Transfer-Encoding, Content-Type and Cookie.")
        self._ck_cookies = scope_box("Cookies", False,
            "Each cookie value separately.")

        r1.add(Box.createHorizontalStrut(14))
        r1.add(mk_lbl("Mode:", 12, True))
        self._rb_replace = mk_radio("Replace", sel=True)
        self._rb_append  = mk_radio("Append")
        self._rb_replace.setToolTipText("Send the payload as the whole value.")
        self._rb_append.setToolTipText(
            "Append the payload to the value already there - what the fragment "
            "payloads below are written for.")
        grp = ButtonGroup(); grp.add(self._rb_replace); grp.add(self._rb_append)
        r1.add(self._rb_replace); r1.add(self._rb_append)

        r1.add(Box.createHorizontalStrut(14))
        self._ck_keep = JCheckBox("Keep all responses", False)
        self._ck_keep.setBackground(BG); self._ck_keep.setForeground(FG)
        self._ck_keep.setToolTipText(
            "Off (recommended): only rows with a flag (SQLERR / 5xx / NO-RESP / "
            "SLOW) keep their response for the viewer - findings are always kept. "
            "On: every payload's response is retained.")
        r1.add(self._ck_keep)
        self._ck_plus = JCheckBox("+ = space (JSON)", True)
        self._ck_plus.setBackground(BG); self._ck_plus.setForeground(FG)
        self._ck_plus.setToolTipText(
            "Payloads use + where a space is needed. A URL query string or form "
            "body is url-decoded by the server, so + arrives as a space on its "
            "own; nothing decodes a JSON string value, so turn + into a real "
            "space before it goes into the body. Payloads are never "
            "percent-encoded either way.")
        r1.add(self._ck_plus)
        b_reset = mk_btn("Reset Payloads", BG3, FG)
        b_reset.addActionListener(lambda e: self._reset_payloads())
        r1.add(b_reset)

        self._btn_simple = mk_btn("  Simple Scan  ", ACCENT)
        self._btn_simple.setToolTipText(
            "One %s into every selected parameter and nothing else - quiet "
            "enough for WAF-heavy targets. Still reports DB errors and 5xx; "
            "no sleeps, so nothing takes 20 seconds." % SIMPLE_PAYLOAD)
        self._btn_simple.addActionListener(lambda e: self._start_simple())
        r2.add(self._btn_simple)
        self._btn_start = mk_btn("  Full Scan  ", GREEN)
        self._btn_start.setToolTipText(
            "Every payload in the list above, including the 20s sleeps.")
        self._btn_start.addActionListener(lambda e: self._start())
        r2.add(self._btn_start)
        self._btn_stop = mk_btn("  Stop  ", RED)
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(lambda e: self._stop())
        r2.add(self._btn_stop)
        r2.add(Box.createHorizontalStrut(10))
        self._prog = JProgressBar(0, 100)
        self._prog.setStringPainted(True); self._prog.setString("Idle")
        self._prog.setPreferredSize(Dimension(260, 22))
        self._prog.setBackground(BG3); self._prog.setForeground(ACCENT)
        r2.add(self._prog)

        bot = JPanel(GridBagLayout())
        bot.setBackground(BG)
        gb = GridBagConstraints()
        gb.gridx = 0; gb.weightx = 1.0
        gb.fill = GridBagConstraints.HORIZONTAL
        gb.gridy = 0; bot.add(r1, gb)
        gb.gridy = 1; bot.add(r2, gb)
        p.add(bot, BorderLayout.SOUTH)
        return p

    # -----------------------------------------------------------------------
    # Results tab
    # -----------------------------------------------------------------------
    def _build_results(self):
        p = JPanel(BorderLayout(5, 5))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        top.setBackground(BG)
        top.add(mk_lbl("Search:"))
        self._search = mk_field("", 28)
        self._search.getDocument().addDocumentListener(SearchDoc(self))
        top.add(self._search)
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_repeater(self._res_table, self._res_model, self._stored))
        top.add(b_rep)
        b_clr = mk_btn("Clear Results", BG3, FG)
        b_clr.addActionListener(lambda e: self._clear())
        top.add(b_clr)
        p.add(top, BorderLayout.NORTH)

        self._res_model = ResultModel()
        self._res_table = JTable(self._res_model)
        style_table(self._res_table)
        sorter = TableRowSorter(self._res_model)
        numc = NumComparator()
        for ci in NUMERIC_COLS:
            sorter.setComparator(ci, numc)
        self._res_table.setRowSorter(sorter)
        rend = FindingRenderer()
        for i in range(self._res_model.getColumnCount()):
            self._res_table.getColumnModel().getColumn(i).setCellRenderer(rend)
        for i, w in enumerate([36, 150, 100, 52, 190, 52, 50, 62, 62, 52, 90, 90]):
            self._res_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._res_table.getSelectionModel().addListSelectionListener(ResultRowSel(self))

        tscroll = JScrollPane(self._res_table)
        tscroll.getViewport().setBackground(BG2)
        tscroll.setBorder(BorderFactory.createLineBorder(BORDER))

        self._req_view  = MessageView("Request")
        self._resp_view = MessageView("Response")
        rr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._req_view, self._resp_view)
        rr.setResizeWeight(0.5); rr.setDividerSize(4); rr.setBackground(BG)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tscroll, rr)
        split.setResizeWeight(0.55); split.setDividerSize(4); split.setBackground(BG)
        p.add(split, BorderLayout.CENTER)
        return p

    # -----------------------------------------------------------------------
    # Findings tab — auto-detected anomalies
    # -----------------------------------------------------------------------
    def _build_findings(self):
        p = JPanel(BorderLayout(5, 5))
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        top.setBackground(BG)
        top.add(mk_lbl("DB error signatures (regex)  -  HTTP 5xx / dead responses  -  time-based delays",
                       11, color=FG_DIM))
        b_rep = mk_btn("Send to Repeater", ACCENT)
        b_rep.addActionListener(lambda e: self._send_repeater(self._f_table, self._f_model, self._f_stored))
        top.add(b_rep)
        b_clr = mk_btn("Clear", BG3, FG)
        b_clr.addActionListener(lambda e: self._clear_findings())
        top.add(b_clr)
        p.add(top, BorderLayout.NORTH)

        self._f_model = FindingsModel()
        self._f_table = JTable(self._f_model)
        style_table(self._f_table)
        fsorter = TableRowSorter(self._f_model)
        fsorter.setComparator(0, NumComparator())
        self._f_table.setRowSorter(fsorter)
        frend = FindingsRenderer()
        for i in range(self._f_model.getColumnCount()):
            self._f_table.getColumnModel().getColumn(i).setCellRenderer(frend)
        for i, w in enumerate([34, 92, 62, 140, 100, 50, 180, 40, 420]):
            self._f_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._f_table.getSelectionModel().addListSelectionListener(FindingRowSel(self))

        tscroll = JScrollPane(self._f_table)
        tscroll.getViewport().setBackground(BG2)
        tscroll.setBorder(BorderFactory.createLineBorder(BORDER))

        self._f_req_view  = MessageView("Request")
        self._f_resp_view = MessageView("Response")
        rr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._f_req_view, self._f_resp_view)
        rr.setResizeWeight(0.5); rr.setDividerSize(4); rr.setBackground(BG)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tscroll, rr)
        split.setResizeWeight(0.5); split.setDividerSize(4); split.setBackground(BG)
        p.add(split, BorderLayout.CENTER)
        return p

    # -----------------------------------------------------------------------
    # Send selected row's request to Burp Repeater
    # -----------------------------------------------------------------------
    def _send_repeater(self, table, model, stored):
        r = table.getSelectedRow()
        if r < 0:
            return
        mr = table.convertRowIndexToModel(r)
        n  = model.getValueAt(mr, 0)
        data = stored.get(int(str(n)))
        if not data:
            return
        req_str, resp_str, svc, modified = data
        if svc is None or modified is None:
            return
        try:
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https", modified, "SQLi " + str(n))
        except Exception as ex:
            print("[SQLi Tester v4] sendToRepeater failed: %s" % ex)

    # -----------------------------------------------------------------------
    # Findings detection + display
    # -----------------------------------------------------------------------
    TIME_MIN_DELTA = 3.0     # a hit must clear the baseline by this much, but
                             # never by more than half the sleep it asked for
    SLOW_FLAG_PCT  = 0.60    # Results "SLOW" flag at this fraction of the sleep

    def _evaluate(self, entry, it, where, payload, status, length, elapsed_ms,
                  err_hits, req_str, resp_str, modified, append, err_note=None):
        """Turn one response into findings.  Three signals only: database error
        strings, 5xx / dead responses, and measured delays."""
        path      = entry["path"]
        pname     = it["name"]
        svc       = entry["svc"]
        base      = self._get_baseline(entry)
        elapsed_s = elapsed_ms / 1000.0
        want      = payload_sleep_secs(payload, self._sleep_secs) if self._opt_time else None
        timed_out = (status == "ERR")

        # ---- 1. database error strings ------------------------------------
        if err_hits and self._opt_sqlerr:
            base_err = set(d for (d, _s) in ((base or {}).get("errs") or []))
            fresh    = [(d, s) for (d, s) in err_hits if d not in base_err]
            use      = fresh or err_hits
            dbms     = ", ".join(sorted(set(d for d, _s in use)))
            if fresh:
                sev = "High" if use[0][0] != "Generic" else "Medium"
                ev  = "%s  |  %s" % (dbms, use[0][1])
            else:
                sev = "Low"
                ev  = "%s  |  %s  (same error without any payload - not injected)" % (
                    dbms, use[0][1])
            self._add_finding("SQL Error", sev, path, pname, where, payload, ev,
                              req_str, resp_str, svc, modified)

        # ---- 2. time-based delay ------------------------------------------
        time_hit = False
        if want:
            time_hit = self._check_time(entry, it, where, payload, want, elapsed_s,
                                        base, req_str, resp_str, modified, append,
                                        timed_out)

        # ---- 3. 5xx / no response -----------------------------------------
        if self._opt_http5xx and not time_hit:
            bstat = str((base or {}).get("status") or "")
            if timed_out:
                ev = "no response after %.1fs" % elapsed_s
                if err_note:
                    ev += "  (%s)" % err_note[:120]
                self._add_finding("No Response", "Medium", path, pname, where,
                                  payload, ev, req_str, resp_str, svc, modified)
            elif status[:1] == "5":
                if bstat[:1] == "5":
                    sev = "Low"
                    ev  = "HTTP %s  (endpoint already returns %s with no payload)" % (status, bstat)
                else:
                    sev = "High"
                    ev  = "HTTP %s  (baseline %s)" % (status, bstat or "?")
                if err_hits:
                    ev += "  [%s]" % err_hits[0][1][:90]
                self._add_finding("Server Error", sev, path, pname, where, payload,
                                  ev, req_str, resp_str, svc, modified)

        # ---- 4. any other status change (optional, noisy) ------------------
        if self._opt_status and not timed_out and status[:1] != "5":
            bstat = str((base or {}).get("status") or "")
            if bstat and bstat != status:
                self._add_finding("Status Change", "Low", path, pname, where, payload,
                                  "HTTP %s -> %s" % (bstat, status),
                                  req_str, resp_str, svc, modified)

    def _check_time(self, entry, it, where, payload, want, elapsed_s, base,
                    req_str, resp_str, modified, append, timed_out):
        """Flag a response that stalled for roughly as long as the payload asked
        for.  Returns True when a finding was raised."""
        bl    = float((base or {}).get("elapsed") or 0.0)
        # Two bars: a fraction of the requested sleep, and a clear margin over
        # how long this endpoint takes anyway.  The margin is capped at half the
        # sleep so short sleeps stay detectable.
        margin = min(self.TIME_MIN_DELTA, want * 0.5)
        floor  = max(want * (self._time_pct / 100.0), bl + margin)
        if elapsed_s < floor:
            return False

        detail = "waited %.1fs for a %.0fs sleep (baseline %.1fs, threshold %.1fs)" % (
            elapsed_s, want, bl, floor)
        sev = "High" if elapsed_s >= want * 0.85 else "Medium"
        # Confirming costs two more slow requests, so exactly one payload per
        # parameter pays for it - the rest just bump that finding's Hits count.
        ckey, mine = ("Time-based", entry["path"], it["name"], where), False
        if self._opt_confirm and not timed_out:
            with self._lock:
                if ckey not in self._fseen and ckey not in self._confirming:
                    self._confirming.add(ckey)
                    mine = True
        if timed_out:
            # Burp gave up before the query finished - that is still a delay.
            detail += "  [connection timed out while the query was sleeping; " \
                      "raise Burp's HTTP timeout above %ds for a clean read]" % int(want)
            sev = "Medium"

        # Post the row now - the re-test below takes two more full sleeps, and
        # the finding should be visible while that runs.
        self._add_finding("Time-based", sev, entry["path"], it["name"], where, payload,
                          detail + ("  |  re-testing..." if mine else ""),
                          req_str, resp_str, entry["svc"], modified)

        if mine:
            try:
                ok, note = self._confirm_time(entry, it, payload, want, floor, append)
            finally:
                with self._lock:
                    self._confirming.discard(ckey)
            self._update_finding(ckey, "High" if ok else "Medium", detail + "  |  " + note)
        return True

    def _confirm_time(self, entry, it, payload, want, floor, append):
        """Re-send the sleeping payload, then the same payload with its delay set
        to 0.  A real time-based injection delays again and the 0s control does
        not - that rules out an endpoint that is simply slow.  Both are judged
        against the same threshold the first hit had to clear."""
        try:
            r1 = self._send(entry, it, payload, append)
            a  = r1["elapsed"]
            # A timeout on the re-test still means the query stalled.
            hit1 = (a >= floor) or (r1["status"] == "ERR" and a >= floor * 0.8)

            ctrl_pl = retime_payload(payload, 0)
            lbl     = "sleep(0)" if ctrl_pl is not None else "no payload"
            r2      = self._send(entry, it, ctrl_pl, append)
            c       = r2["elapsed"]
            fast    = c < floor

            return (hit1 and fast), "re-test %.1fs, %s control %.1fs -> %s" % (
                a, lbl, c, "CONFIRMED" if (hit1 and fast) else "not reproducible")
        except Exception as ex:
            return False, "re-test failed: %s" % ex

    def _get_baseline(self, entry):
        """Unmodified request: status, fastest round trip, and any DB error the
        endpoint already prints on its own.  Cached per queued request."""
        key = id(entry)
        with self._bl_lock:
            if key in self._baseline:
                return self._baseline[key]
            data = None
            try:
                best, status, length, body = None, "ERR", 0, ""
                for _ in range(max(1, self._bl_probes)):
                    self._rate_gate()
                    self._count_sent()
                    t0   = time.time()
                    resp = self._cb.makeHttpRequest(entry["svc"], entry["req"])
                    el   = time.time() - t0
                    rb   = resp.getResponse()
                    if best is None or el < best:
                        best = el
                    if rb:
                        ri     = self._h.analyzeResponse(rb)
                        status = str(ri.getStatusCode())
                        length = len(rb)
                        body   = self._h.bytesToString(rb)
                data = {"status": status, "len": length, "elapsed": best or 0.0,
                        "errs": sql_error_hits(body, self._opt_generic)}
                print("[SQLi Tester v4] baseline %s %s -> %s, %.2fs, %d pre-existing "
                      "error(s)  [%d request(s)]"
                      % (entry["method"], entry["path"], status, data["elapsed"],
                         len(data["errs"]), max(1, self._bl_probes)))
            except Exception as ex:
                print("[SQLi Tester v4] baseline fetch failed: %s" % ex)
            self._baseline[key] = data
            return data

    def _add_finding(self, ftype, sev, path, pname, where, payload, evidence,
                     req_str, resp_str, svc, modified):
        """One row per (type, request, parameter).  Repeats of the same signal
        bump the Hits counter instead of adding another row."""
        key = (ftype, path, pname, where)
        with self._lock:
            if key in self._fseen:
                fid = self._fseen[key]
                self._fhits[fid] = self._fhits.get(fid, 1) + 1
                # coalesced: only the latest count is ever drawn
                self._pend_hits[fid] = self._fhits[fid]
                return
            fid = len(self._findings) + 1
            self._fseen[key] = fid
            self._fhits[fid] = 1
            self._findings.append(key)
            self._f_stored[fid] = (req_str, resp_str, svc, modified)
            self._pend_frows.append(
                [fid, ftype, sev, path, pname, where, payload, 1, evidence])

    def _update_finding(self, key, sev, evidence):
        """Rewrite an existing finding's severity and evidence (used once a
        time-based hit has been re-tested)."""
        with self._lock:
            fid = self._fseen.get(key)
            if fid:
                self._pend_cells[fid] = (sev, evidence)

    def _drain(self):
        """EDT only. Everything the worker threads produced since the last tick,
        applied in one go: result rows (respecting the search box), new finding
        rows, coalesced hit counts, re-test rewrites, and one progress update.

        Finding rows are located through _frow_of rather than by scanning the
        model, which is what made a noisy endpoint crawl: v2 walked every
        findings row for every repeat of every signal, on the EDT."""
        with self._lock:
            rows,  self._pending    = self._pending, []
            frows, self._pend_frows = self._pend_frows, []
            hits,  self._pend_hits  = self._pend_hits, {}
            cells, self._pend_cells = self._pend_cells, {}
            done, total, kept = self._done, self._total, self._kept
        sent = self._sent
        q = self._query

        for row in rows:
            if not q or any(q in str(c).lower() for c in row):
                self._res_model.addRow(row)
        for row in frows:
            self._frow_of[row[0]] = self._f_model.getRowCount()
            self._f_model.addRow(row)
        if frows:
            try:
                self._tabs.setTitleAt(self._findings_tab_index,
                                      "  Findings (%d)  " % self._f_model.getRowCount())
            except Exception:
                pass
        for fid in hits:
            i = self._frow_of.get(fid)
            if i is not None:
                self._f_model.setValueAt(hits[fid], i, 7)
        for fid in cells:
            i = self._frow_of.get(fid)
            if i is not None:
                sev, ev = cells[fid]
                self._f_model.setValueAt(sev, i, 2)
                self._f_model.setValueAt(ev, i, 8)
        if total:
            self._prog.setValue(int(done * 100.0 / total))
            self._prog.setString(self._progress_text(done, total, sent, kept))

    def _progress_text(self, done, total, sent, kept):
        """What the bar says. "probes" is work items finished, "req" is requests
        actually sent - they differ because of baselines and re-tests - and
        "rows" is what the table is holding, so a search filter can never make
        the numbers look like lost results again."""
        shown = self._res_model.getRowCount()
        txt = "%d / %d probes  |  %d req sent  |  %d row(s)" % (done, total, sent, shown)
        if self._query:
            txt += " shown of %d" % len(self._rows)
        if kept:
            txt += "  |  %.1f MB" % (kept / 1048576.0)
        return txt

    def _start_drain(self):
        if self._timer is None:
            self._timer = Timer(DRAIN_MS, DrainTick(self))
            self._timer.setRepeats(True)
        self._timer.start()

    def _stop_drain(self):
        if self._timer is not None:
            self._timer.stop()

    def _sort_by_id(self):
        """Keep the table in # order. Rows finish out of order with several
        threads running, and v2 appended them in completion order, so the #
        column looked shuffled and rows seemed to be missing."""
        try:
            keys = ArrayList()
            keys.add(RowSorter.SortKey(0, SortOrder.ASCENDING))
            self._res_table.getRowSorter().setSortKeys(keys)
        except Exception as ex:
            print("[SQLi Tester v4] sort error: %s" % ex)

    def _show_finding_pair(self, view_row):
        mr = self._f_table.convertRowIndexToModel(view_row)
        n  = self._f_model.getValueAt(mr, 0)
        if n is not None:
            data = self._f_stored.get(int(str(n)))
            if data:
                self._f_req_view.set_text(data[0])
                self._f_resp_view.set_text(data[1])

    def _reset_findings_ui(self):
        """Clear only the Swing model/title (safe to schedule before worker threads add rows)."""
        self._f_model.setRowCount(0)
        self._frow_of = {}
        self._f_req_view.set_text(""); self._f_resp_view.set_text("")
        try:
            self._tabs.setTitleAt(self._findings_tab_index, "  Findings  ")
        except Exception:
            pass

    def _clear_findings(self):
        self._findings = []; self._f_stored = {}
        self._fseen = {}; self._fhits = {}; self._confirming = set()
        self._reset_findings_ui()

    # -----------------------------------------------------------------------
    # Request engine + rate limiting
    # -----------------------------------------------------------------------
    def _set_rate(self):
        """Global cap on how fast requests leave the extension."""
        try:
            mr = float(self._f_maxrps.getText().strip() or "0")
        except Exception:
            mr = 0.0
        if mr <= 0 or mr > RPS_CAP:
            mr = RPS_CAP
            SwingUtilities.invokeLater(
                lambda: self._f_maxrps.setText(str(int(RPS_CAP))))
        self._rl_interval = 1.0 / mr
        with self._rl_lock:
            self._rl_next = 0.0

    def _count_sent(self):
        """Every request that leaves, from any phase: probe, baseline or
        confirmation re-test. v2 only ever counted probe rows, so the number it
        printed at the end was never the number of requests it had sent."""
        with self._cnt_lock:
            self._sent += 1
            return self._sent

    def _rate_gate(self):
        """Block until this thread is allowed to fire, enforcing the global cap."""
        iv = self._rl_interval
        if iv <= 0:
            return
        with self._rl_lock:
            now = time.time()
            if self._rl_next <= now:
                self._rl_next = now + iv
                wait = 0.0
            else:
                wait = self._rl_next - now
                self._rl_next += iv
        if wait > 0:
            time.sleep(wait)

    def _send(self, entry, it, payload, append):
        """Fire one request.  payload=None sends the original, untouched."""
        if payload is None:
            modified = entry["req"]
        else:
            val = (it["value"] + payload) if append else payload
            modified = self._inject(entry["raw"], it, val)
        self._rate_gate()
        self._count_sent()
        t0 = time.time()
        try:
            resp = self._cb.makeHttpRequest(entry["svc"], modified)
            rb   = resp.getResponse()
        except Exception as ex:
            print("[SQLi Tester v4] send failed: %s" % ex)
            rb = None
        el = time.time() - t0
        rs = self._h.bytesToString(rb) if rb else ""
        ri = self._h.analyzeResponse(rb) if rb else None
        return {"status": str(ri.getStatusCode()) if ri else "ERR",
                "len": len(rb) if rb else 0, "resp": rs, "elapsed": el,
                "bytes": modified, "req": self._h.bytesToString(modified)}

    # -----------------------------------------------------------------------
    # Settings tab
    # -----------------------------------------------------------------------
    def _build_settings(self):
        p = JPanel(GridBagLayout())
        p.setBackground(BG)
        p.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18))
        g = GridBagConstraints()
        g.insets = Insets(7, 8, 7, 8)
        g.anchor = GridBagConstraints.WEST
        row = [0]

        def add_row(label, widget):
            g.gridx = 0; g.gridy = row[0]; g.gridwidth = 1; g.fill = GridBagConstraints.NONE
            p.add(mk_lbl(label), g)
            g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL
            p.add(widget, g)
            row[0] += 1

        def add_note(text, color=FG_DIM):
            g.gridx = 0; g.gridy = row[0]; g.gridwidth = 2
            g.fill = GridBagConstraints.HORIZONTAL
            p.add(mk_lbl(text, 11, color=color), g)
            g.gridwidth = 1
            row[0] += 1

        def add_check(label, text, sel, tip=""):
            cb = JCheckBox(text, sel)
            cb.setBackground(BG); cb.setForeground(FG)
            cb.setFont(Font("Segoe UI", Font.PLAIN, 12))
            if tip:
                cb.setToolTipText(tip)
            add_row(label, cb)
            return cb

        add_note("REQUESTS", ACCENT)
        self._f_threads = mk_field("5", 6)
        add_row("Threads (concurrent):", self._f_threads)
        self._f_maxrps = mk_field(str(int(RPS_CAP)), 6)
        self._f_maxrps.setToolTipText(
            "Hard capped at %d req/sec - higher values are clamped." % int(RPS_CAP))
        add_row("Max requests/sec (cap %d):" % int(RPS_CAP), self._f_maxrps)

        add_note(" ")
        add_note("DETECTION", ACCENT)
        self._f_sleep = mk_field(str(SLEEP_SECS), 6)
        self._f_sleep.setToolTipText(
            "Used for payloads whose stall cannot be read from the payload text "
            "(BENCHMARK, RANDOMBLOB...). SLEEP(n) payloads use their own n.")
        add_row("Sleep payload length (seconds):", self._f_sleep)
        self._f_timepct = mk_field("60", 6)
        self._f_timepct.setToolTipText(
            "A 20s sleep with this set to 60 flags anything that takes 12s or more.")
        add_row("Flag a delay at (% of the sleep):", self._f_timepct)

        self._ck_sqlerr = add_check("Report DB error strings:",
                                    "regex signatures for MySQL / PostgreSQL / MSSQL / Oracle / "
                                    "SQLite / DB2 / ORMs", True)
        self._ck_generic = add_check("...including generic parser noise:",
                                     "\"syntax error\", \"parse error\" etc. - noisy on "
                                     "GraphQL / JSON APIs", False)
        self._ck_http5xx = add_check("Report HTTP 5xx / no response:",
                                     "500-599, dropped connections and timeouts", True)
        self._ck_time = add_check("Report time-based delays:",
                                  "response stalls for roughly as long as the payload asked", True)
        self._ck_confirm = add_check("Confirm time hits:",
                                     "re-send the payload, then the same payload with sleep(0)",
                                     True)
        self._ck_statuschg = add_check("Report other status changes:",
                                       "e.g. baseline 200 -> 403 with a payload (noisy)", False)

        add_note(" ")
        add_note("SITE MAP IMPORT", ACCENT)
        self._ck_imp_static = add_check(
            "Skip static files:",
            "images / fonts / css / js that carry no parameters", False,
            "Off (default): everything the host has is queued. On: a static "
            "file with no query string and no body is skipped - there is "
            "nothing in it to inject into.")
        self._ck_imp_noparam = add_check(
            "Skip requests with nothing to inject:",
            "no parameter in any class ticked above", False,
            "Off (default): queued anyway, and simply contributes no probes "
            "until a parameter class that matches it is ticked. On: skipped at "
            "import time.")
        self._ck_imp_dedupe = add_check(
            "One entry per injection surface:",
            "/s?q=1 and /s?q=2 collapse into one", False,
            "Off (default): every recorded request is queued. On: requests "
            "that differ only in parameter values collapse, since injecting "
            "into q is the same test either way. Byte-identical requests are "
            "dropped either way.")
        self._ck_reset_send = add_check(
            "Clear everything on new Send:",
            "wipe the queue, Results and Findings first", True,
            "On (default): each new 'Send to SQLi Tester v4' clears the queue "
            "and both result tabs (Results and Findings) before queueing, so "
            "you start clean without clicking Clear each time. Off: new sends "
            "add to the current queue and keep existing results, for building a "
            "queue from several hosts.")

        add_note(" ")
        add_note("Each endpoint is baselined first for status, latency and errors it "
                 "already prints: 2 unmodified requests when the run has a time-based "
                 "payload in it, 1 otherwise (Simple Scan).")
        add_note("Burp's HTTP timeout must be longer than the sleep: Settings > Network > "
                 "Connections > HTTP timeouts (default 120s is fine for 20s sleeps).")

        g.gridwidth = 1; g.gridx = 1; g.gridy = row[0]; g.fill = GridBagConstraints.NONE
        b = mk_btn("  Save Settings  ", ACCENT)
        b.addActionListener(lambda e: self._save_settings())
        p.add(b, g)
        return p

    def _read_opts(self):
        """Pull the detection settings into plain fields the worker threads read."""
        def num(field, default, lo, hi):
            try:
                v = float(field.getText().strip())
            except Exception:
                v = default
            return max(lo, min(hi, v))
        self._sleep_secs  = num(self._f_sleep,   float(SLEEP_SECS), 1.0, 300.0)
        self._time_pct    = num(self._f_timepct, 60.0, 10.0, 100.0)
        self._opt_sqlerr  = self._ck_sqlerr.isSelected()
        self._opt_generic = self._ck_generic.isSelected()
        self._opt_http5xx = self._ck_http5xx.isSelected()
        self._opt_time    = self._ck_time.isSelected()
        self._opt_confirm = self._ck_confirm.isSelected()
        self._opt_status  = self._ck_statuschg.isSelected()

    def _reset_payloads(self):
        """Restore the built-in list, retimed to the configured sleep length."""
        try:
            secs = int(float(self._f_sleep.getText().strip()))
        except Exception:
            secs = SLEEP_SECS
        out = []
        for pl in DEFAULT_PAYLOADS:
            out.append(retime_payload(pl, secs) or pl)
        self._payload_area.setText("\n".join(out))
        self._set_status("Payloads reset (%ds sleeps)." % secs, GREEN)

    # -----------------------------------------------------------------------
    # Settings
    # -----------------------------------------------------------------------
    def _save_settings(self):
        s = self._cb.saveExtensionSetting
        s("payload_mode", "append" if self._rb_append.isSelected() else "replace")
        s("scope_url",    str(self._ck_url.isSelected()))
        s("scope_body",   str(self._ck_body.isSelected()))
        s("cookies",      str(self._ck_cookies.isSelected()))
        s("headers",      str(self._ck_headers.isSelected()))
        s("plus_space",   str(self._ck_plus.isSelected()))
        s("keep_all",     str(self._ck_keep.isSelected()))
        s("threads",      self._f_threads.getText())
        s("maxrps",       self._f_maxrps.getText())
        s("sleep_secs",   self._f_sleep.getText())
        s("time_pct",     self._f_timepct.getText())
        s("opt_sqlerr",   str(self._ck_sqlerr.isSelected()))
        s("opt_generic",  str(self._ck_generic.isSelected()))
        s("opt_http5xx",  str(self._ck_http5xx.isSelected()))
        s("opt_time",     str(self._ck_time.isSelected()))
        s("opt_confirm",  str(self._ck_confirm.isSelected()))
        s("opt_status",   str(self._ck_statuschg.isSelected()))
        s("imp_static",   str(self._ck_imp_static.isSelected()))
        s("imp_noparam",  str(self._ck_imp_noparam.isSelected()))
        s("imp_dedupe",   str(self._ck_imp_dedupe.isSelected()))
        s("reset_send",   str(self._ck_reset_send.isSelected()))
        # v2: payloads now use real spaces instead of '+' and 20s sleeps
        s("payloads_v2",  self._payload_area.getText())
        self._set_status("Settings saved.", GREEN)

    def _load_settings(self):
        def get(k, d):
            v = self._cb.loadExtensionSetting(k)
            return v if v is not None else d
        def flag(k, d):
            return get(k, d) == "True"
        mode = get("payload_mode", "replace")
        self._rb_append.setSelected(mode == "append")
        self._rb_replace.setSelected(mode != "append")
        self._ck_url.setSelected(flag("scope_url", "True"))
        self._ck_body.setSelected(flag("scope_body", "True"))
        self._ck_cookies.setSelected(flag("cookies", "False"))
        self._ck_headers.setSelected(flag("headers", "False"))
        self._ck_plus.setSelected(flag("plus_space", "True"))
        self._ck_keep.setSelected(flag("keep_all", "False"))
        self._f_threads.setText(get("threads", "5"))
        self._f_maxrps.setText(get("maxrps", str(int(RPS_CAP))))
        self._f_sleep.setText(get("sleep_secs", str(SLEEP_SECS)))
        self._f_timepct.setText(get("time_pct", "60"))
        self._ck_sqlerr.setSelected(flag("opt_sqlerr", "True"))
        self._ck_generic.setSelected(flag("opt_generic", "False"))
        self._ck_http5xx.setSelected(flag("opt_http5xx", "True"))
        self._ck_time.setSelected(flag("opt_time", "True"))
        self._ck_confirm.setSelected(flag("opt_confirm", "True"))
        self._ck_statuschg.setSelected(flag("opt_status", "False"))
        self._ck_imp_static.setSelected(flag("imp_static", "False"))
        self._ck_imp_noparam.setSelected(flag("imp_noparam", "False"))
        self._ck_imp_dedupe.setSelected(flag("imp_dedupe", "False"))
        self._ck_reset_send.setSelected(flag("reset_send", "True"))
        saved = get("payloads_v2", "")
        if saved.strip():
            self._payload_area.setText(saved)
        self._read_opts()

    def _set_status(self, msg, color=FG_DIM):
        self._status_lbl.setText(msg)
        self._status_lbl.setForeground(color)

    # -----------------------------------------------------------------------
    # Context menu — receives highlighted requests
    # -----------------------------------------------------------------------
    def createMenuItems(self, inv):
        lst = ArrayList()
        item = JMenuItem("Send to SQLi Tester v4")
        item.addActionListener(lambda e: self._recv(inv))
        lst.add(item)
        rec = JMenuItem("Send whole host(s) from site map to SQLi Tester v4")
        rec.addActionListener(lambda e: self._recv_sitemap(inv))
        lst.add(rec)
        return lst

    def _msg_url(self, msg):
        """The URL of a site map entry.

        getUrl() first, deprecated or not: a host or folder node in the Site
        map has a URL but often no request bytes behind it, and in that case
        analyzeRequest() gives nothing - which is exactly why deriving the URL
        through the helpers alone silently found no hosts to expand."""
        try:
            u = msg.getUrl()
            if u is not None:
                return strip_default_port(str(u))
        except Exception:
            pass
        try:
            u = self._h.analyzeRequest(msg).getUrl()
            if u is not None:
                return strip_default_port(str(u))
        except Exception:
            pass
        return ""

    def _selection_prefixes(self, inv):
        """Where to pull the site map from, for whatever the user right-clicked.

        Two sources, because neither covers every case on its own: the Site map
        tree selection (the only thing that sees a host or folder node), and
        the selected messages (the only thing that works in the site map table,
        proxy history, Repeater and so on)."""
        try:
            ctx = inv.getInvocationContext()
        except Exception:
            ctx = -1
        prefixes = []
        msgs = []
        try:
            msgs = list(inv.getSelectedMessages() or [])
        except Exception:
            msgs = []
        # A Site map tree selection hands back one entry per selected node, and
        # that node's own URL is the branch to expand - a host node gives
        # "https://host", a folder node "https://host/api". Anywhere else (site
        # map table, proxy history, Repeater) the selection is real requests, so
        # the host they belong to is what "whole host" means.
        tree_ctx = (ctx == CTX_SITE_MAP_TREE)
        for msg in msgs:
            u = self._msg_url(msg)
            if not u:
                continue
            r = u if tree_ctx else url_host_root(u)
            if r not in prefixes:
                prefixes.append(r)

        # Only if that found nothing: read the selection off the tree component.
        tree = None
        if not prefixes:
            try:
                tree = jtree_from_event(inv.getInputEvent())
            except Exception as ex:
                print("[SQLi Tester v4] could not reach the site map tree: %s" % ex)
            if tree is not None:
                prefixes = tree_prefixes(tree)
                if not prefixes:
                    for labels in tree_selection_labels(tree):
                        print("[SQLi Tester v4] unrecognised site map node: %r" % (labels,))

        prefixes = drop_nested(prefixes)
        print("[SQLi Tester v4] context=%s, %d selected message(s), tree=%s, "
              "%d branch(es): %s"
              % (ctx, len(msgs), "yes" if tree is not None else "no",
                 len(prefixes), ", ".join(prefixes) or "-"))
        return prefixes


    def _recv_sitemap(self, inv):
        """Every request Burp has recorded for the selected host(s).

        Only the host is taken from the selection - the items come from
        getSiteMap(), so it does not matter whether the click was on a host
        node, a folder or a single request, or which Burp version is deciding
        what a tree selection means."""
        try:
            roots = self._selection_prefixes(inv)
            if not roots:
                self._set_status("Nothing usable in that selection - highlight a "
                                 "host (or any request under it) in the Site map.", RED)
                return

            items = []
            for r in roots:
                try:
                    got = list(self._cb.getSiteMap(r) or [])
                except Exception as ex:
                    print("[SQLi Tester v4] getSiteMap(%s) failed: %s" % (r, ex))
                    continue
                # getSiteMap matches on the URL text, so a bare host prefix also
                # matches a different host that merely starts the same way.
                want = url_authority(r)
                keep = []
                for m in got:
                    u = self._msg_url(m)
                    if not u or (want and url_authority(u) != want):
                        continue
                    keep.append(m)
                print("[SQLi Tester v4] site map %s -> %d item(s)%s"
                      % (r, len(keep),
                         "  (%d other host(s) ignored)" % (len(got) - len(keep))
                         if len(got) != len(keep) else ""))
                items.extend(keep)
            if not items:
                print("[SQLi Tester v4] site map has nothing under %s - queueing "
                      "the selection instead." % ", ".join(roots))
                self._recv(inv)        # does its own reset
                return

            # About to add a fresh batch: clear first, if asked. Before the
            # 'seen' set so it starts from an empty queue.
            self._reset_if_enabled()
            scope = self._scope()
            f_static  = self._ck_imp_static.isSelected()
            f_noparam = self._ck_imp_noparam.isSelected()
            f_surface = self._ck_imp_dedupe.isSelected()
            seen  = set(self._endpoint_sig(e, f_surface) for e in self._queue)
            added = dupes = static = noparam = bad = norequest = 0
            capped = False
            self._quiet = True
            try:
                for msg in items:
                    if added >= MAX_IMPORT:
                        capped = True
                        break
                    try:
                        req = msg.getRequest()
                        if req is None:
                            # A tree node Burp drew for a path segment, or a
                            # link it inferred but never requested: it has a URL
                            # and nothing to replay. On a big site map these are
                            # most of what gets skipped.
                            norequest += 1
                            continue
                        u   = self._msg_url(msg)
                        raw = self._h.bytesToString(req)
                        body = self._split_req(raw)[2]
                        if f_static and is_static_url(u, bool(body.strip())):
                            static += 1
                            continue
                        entry = self._load_one(msg, scope)
                        if entry is None:
                            bad += 1
                            continue
                        if f_noparam and not entry["params"]:
                            # nothing in scope to inject into on this one
                            noparam += 1
                            continue
                        sig = self._endpoint_sig(entry, f_surface)
                        if sig in seen:
                            dupes += 1
                            continue
                        seen.add(sig)
                        self._queue.append(entry)
                        self._q_model.addRow([len(self._queue), entry["method"],
                                              entry["host"], entry["path"],
                                              len(entry["params"])])
                        added += 1
                    except Exception as ex:
                        bad += 1
                        print("[SQLi Tester v4] import error: %s" % ex)
            finally:
                self._quiet = False

            notes = []
            if norequest:
                notes.append("%d never requested (folder / inferred link)" % norequest)
            if dupes:
                notes.append("%d %s" % (dupes, "duplicate endpoint(s)" if f_surface
                                        else "identical request(s)"))
            if static:
                notes.append("%d static file(s)" % static)
            if noparam:
                notes.append("%d with nothing in scope to inject" % noparam)
            if bad:
                notes.append("%d unusable" % bad)
            tail = ("  -  skipped " + ", ".join(notes)) if notes else ""
            if capped:
                tail += ("  -  stopped at the %d item cap; narrow the selection "
                         "to queue the rest" % MAX_IMPORT)
            print("[SQLi Tester v4] site map import: queued %d of %d item(s)%s"
                  % (added, len(items), tail))
            self._set_status("Site map import: %d endpoint(s) queued from %d item(s)"
                             "%s  -  %d in queue."
                             % (added, len(items), tail, len(self._queue)),
                             GREEN if added else YELLOW)
            if added:
                self._tabs.setSelectedIndex(0)
                last = self._q_model.getRowCount() - 1
                if last >= 0:
                    self._q_table.setRowSelectionInterval(last, last)
        except Exception as ex:
            print("[SQLi Tester v4] _recv_sitemap error: %s" % ex)

    def _reset_all(self):
        """Wipe the queue, the Results tab and the Findings tab so a new Send
        starts from nothing. Any scan in flight is stopped and its row drain
        halted first, since that output is about to be cleared."""
        self._scan = False
        try:
            self._stop_drain()
        except Exception:
            pass
        self._btn_start.setEnabled(True); self._btn_simple.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._clear_queue()
        self._clear()            # Results + Findings (via _clear_findings)

    def _reset_if_enabled(self):
        """Clear everything when the Settings tab's 'Clear everything on new
        Send' box is ticked. Called at the start of each Send, once there is
        something to queue."""
        try:
            if self._ck_reset_send.isSelected():
                self._reset_all()
        except Exception as ex:
            print("[SQLi Tester v4] reset-on-send failed: %s" % ex)

    def _recv(self, inv):
        try:
            msgs = inv.getSelectedMessages()
            if not msgs:
                self._set_status("No request in selection.", RED)
                return
            print("[SQLi Tester v4] getSelectedMessages() -> %d message(s)" % len(msgs))
            self._reset_if_enabled()        # fresh slate before this batch, if asked
            scope = self._scope()
            existing = set(self._endpoint_sig(e, True) for e in self._queue)
            added = skipped = 0
            for msg in msgs:
                try:
                    entry = self._load_one(msg, scope)
                    if entry is None:
                        continue
                    sig = self._endpoint_sig(entry, True)
                    if sig in existing:
                        skipped += 1
                        continue
                    existing.add(sig)
                    self._queue.append(entry)
                    self._q_model.addRow([len(self._queue), entry["method"],
                                          entry["host"], entry["path"], len(entry["params"])])
                    added += 1
                    print("[SQLi Tester v4] queued: %s %s  (params=%d)" %
                          (entry["method"], entry["path"], len(entry["params"])))
                except Exception as ex:
                    print("[SQLi Tester v4] load error: %s" % ex)

            label = "%d request(s) loaded" % added
            if skipped:
                label += ", %d duplicate(s) skipped" % skipped
            self._set_status("%s  —  %d in queue." % (label, len(self._queue)),
                             GREEN if added else YELLOW)
            if added:
                self._tabs.setSelectedIndex(0)
                # auto-select newest so the detail panel shows it
                last = self._q_model.getRowCount() - 1
                if last >= 0:
                    self._q_table.setRowSelectionInterval(last, last)
        except Exception as ex:
            print("[SQLi Tester v4] _recv error: %s" % ex)

    # -----------------------------------------------------------------------
    # Queue detail / management
    # -----------------------------------------------------------------------
    def _show_queue_detail(self, row):
        if row < 0 or row >= len(self._queue):
            return
        entry = self._queue[row]
        if entry["params"]:
            lines = []
            for it in entry["params"]:
                where = KIND_LABEL.get(it["kind"], it["kind"])
                lines.append("%-22s [%s]  =  %s" % (it["name"], where, it["value"]))
            self._detail_params.setText("\n".join(lines))
        else:
            self._detail_params.setText("(no testable parameters found in this request)")
        self._detail_params.setCaretPosition(0)
        try:
            raw = self._h.bytesToString(entry["req"])
        except Exception:
            raw = ""
        self._detail_raw.setText(raw)
        self._detail_raw.setCaretPosition(0)

    def _recount_params(self):
        scope = self._scope()
        for entry in self._queue:
            try:
                entry["params"] = self._parse_points(entry["raw"], scope)
            except Exception as ex:
                print("[SQLi Tester v4] recount error: %s" % ex)
        for i, entry in enumerate(self._queue):
            self._q_model.setValueAt(len(entry["params"]), i, 4)
        r = self._q_table.getSelectedRow()
        if r >= 0:
            self._show_queue_detail(r)

    def _remove_queued(self):
        rows = sorted(set(self._q_table.getSelectedRows()), reverse=True)
        if not rows:
            return
        for r in rows:
            if 0 <= r < len(self._queue):
                del self._queue[r]
        self._q_model.setRowCount(0)
        for i, entry in enumerate(self._queue):
            self._q_model.addRow(
                [i + 1, entry["method"], entry["host"], entry["path"], len(entry["params"])])
        self._detail_params.setText(""); self._detail_raw.setText("")
        self._set_status("%d request(s) in queue." % len(self._queue), FG_DIM)

    def _clear_queue(self):
        self._queue = []
        self._q_model.setRowCount(0)
        self._detail_params.setText(""); self._detail_raw.setText("")
        self._set_status("Queue cleared.", FG_DIM)

    def _refill_queue_table(self):
        """Redraw the queue from self._queue, renumbering as it goes."""
        self._q_model.setRowCount(0)
        for i, entry in enumerate(self._queue):
            self._q_model.addRow([i + 1, entry["method"], entry["host"],
                                  entry["path"], len(entry["params"])])
        self._detail_params.setText(""); self._detail_raw.setText("")

    def _sort_queue_params(self):
        """Most injection points first. The scan runs top to bottom, so this is
        what puts a site map import's useful half in front."""
        if not self._queue:
            return
        self._queue.sort(key=lambda e: (-len(e["params"]), e["host"], e["path"]))
        self._refill_queue_table()
        counts = [len(e["params"]) for e in self._queue]
        live = sum(1 for c in counts if c)
        self._set_status(
            "Sorted by parameter count: %d of %d request(s) have something to "
            "inject (most has %d)." % (live, len(counts), counts[0] if counts else 0),
            GREEN)

    def _dedupe_queue(self):
        """One entry per injection surface, first occurrence wins."""
        if not self._queue:
            return
        seen, keep = set(), []
        for entry in self._queue:
            sig = self._endpoint_sig(entry, True)
            if sig in seen:
                continue
            seen.add(sig)
            keep.append(entry)
        gone = len(self._queue) - len(keep)
        self._queue = keep
        self._refill_queue_table()
        self._set_status("De-duplicated: %d removed, %d request(s) left."
                         % (gone, len(self._queue)), GREEN if gone else FG_DIM)

    def _drop_noparam(self):
        """Throw out whatever has nothing to inject in the current scope."""
        if not self._queue:
            return
        keep = [e for e in self._queue if e["params"]]
        gone = len(self._queue) - len(keep)
        self._queue = keep
        self._refill_queue_table()
        self._set_status("Dropped %d request(s) with no injection point, %d left."
                         % (gone, len(self._queue)), GREEN if gone else FG_DIM)

    # -----------------------------------------------------------------------
    # Scan
    # -----------------------------------------------------------------------
    def _start_simple(self):
        """One quote per parameter, nothing else."""
        self._start([SIMPLE_PAYLOAD], "simple")

    def _start(self, payloads=None, kind="full"):
        if self._scan:
            return
        if not self._queue:
            self._set_status("Queue is empty — send requests first.", RED); return
        if not any(self._scope().values()):
            self._set_status("Nothing selected to scan — tick GET / POST / "
                             "Headers / Cookies.", RED); return
        if payloads is None:
            # rstrip only: a leading space is meaningful for numeric contexts
            # (" AND SLEEP(20)" appended to  id=42).
            payloads = [l.rstrip() for l in self._payload_area.getText().splitlines()
                        if l.strip() and not l.startswith("##")]
        if not payloads:
            self._set_status("No payloads defined.", RED); return
        total_params = sum(len(e["params"]) for e in self._queue)
        if total_params == 0:
            self._set_status("No testable parameters in queue — check the Scan "
                             "boxes.", RED); return

        self._scan = True
        self._btn_start.setEnabled(False); self._btn_simple.setEnabled(False)
        self._btn_stop.setEnabled(True)
        on = [n for n, v in (("GET", self._ck_url.isSelected()),
                             ("POST", self._ck_body.isSelected()),
                             ("Headers", self._ck_headers.isSelected()),
                             ("Cookies", self._ck_cookies.isSelected())) if v]
        self._set_status(
            "%s scan: %d parameter(s) x %d payload(s) over %s."
            % (kind.capitalize(), total_params, len(payloads), "/".join(on)),
            ACCENT)
        self._tabs.setSelectedIndex(1)
        t = threading.Thread(target=self._worker, args=(list(self._queue), payloads))
        t.setDaemon(True); t.start()

    def _stop(self):
        self._scan = False

    def _worker(self, queue_snapshot, payloads):
        try:
            try:
                n_threads = int(float(self._f_threads.getText().strip() or "5"))
            except Exception:
                n_threads = 5
            n_threads = max(1, min(50, n_threads))
            append   = self._rb_append.isSelected()
            mode_lbl = "append" if append else "replace"
            self._set_rate()
            self._read_opts()

            # Flat work list — every (request, injection point, payload) combo
            work = []
            for entry in queue_snapshot:
                for it in entry["params"]:
                    for payload in payloads:
                        work.append((entry, it, payload))

            self._work   = work
            self._widx   = 0
            self._done   = 0
            self._total  = len(work)
            self._stored = {}
            self._rows   = []
            self._kept   = 0
            self._sent   = 0
            with self._lock:
                self._pending    = []
                self._pend_hits  = {}
                self._pend_cells = {}
                self._pend_frows = []
            # read once here: the worker threads only see self._keep_all
            self._keep_all = self._ck_keep.isSelected()
            # The second baseline request exists only to take the fastest round
            # trip, which nothing but the time-based threshold reads.  A run
            # with no sleep in it - Simple Scan, or an error-only payload list -
            # still needs the baseline for its status and its pre-existing DB
            # errors, but one request answers both.
            self._bl_probes = 2 if (self._opt_time and any(
                payload_sleep_secs(p, self._sleep_secs) for p in payloads)) else 1
            # reset findings for this run (data off-thread; UI via EDT, before threads add rows)
            self._findings = []; self._f_stored = {}
            self._fseen = {}; self._fhits = {}; self._baseline = {}
            self._confirming = set()
            SwingUtilities.invokeLater(lambda: self._res_model.setRowCount(0))
            SwingUtilities.invokeLater(self._reset_findings_ui)
            SwingUtilities.invokeLater(self._sort_by_id)
            SwingUtilities.invokeLater(self._start_drain)
            if self._total == 0:
                SwingUtilities.invokeLater(self._stop_drain)
                return

            # Baseline every endpoint first: status, fastest round trip and any
            # DB error it already prints.  Everything else is judged against it.
            SwingUtilities.invokeLater(
                lambda n=len(queue_snapshot), k=self._bl_probes:
                    self._prog.setString("Baselining %d endpoint(s), %d request(s) each..."
                                         % (n, k)))
            for entry in queue_snapshot:
                if not self._scan:
                    break
                self._get_baseline(entry)

            print("[SQLi Tester v4] scanning %d request(s) with %d thread(s), cap %.1f req/s"
                  % (self._total, n_threads, (1.0 / self._rl_interval) if self._rl_interval else 0))
            pool = []
            for _ in range(n_threads):
                t = threading.Thread(target=self._thread_run, args=(append, mode_lbl))
                t.setDaemon(True)
                pool.append(t)
                t.start()
            for t in pool:
                t.join()
        except Exception as ex:
            print("[SQLi Tester v4] Worker error: %s" % ex)
        finally:
            self._scan = False
            SwingUtilities.invokeLater(self._scan_done)

    def _thread_run(self, append, mode_lbl):
        """One worker thread: pull the next work item and fire it, until none left."""
        while self._scan:
            with self._lock:
                if self._widx >= len(self._work):
                    return
                i = self._widx
                self._widx += 1
            entry, it, payload = self._work[i]
            rid = i + 1
            try:
                where    = KIND_LABEL.get(it["kind"], it["kind"])
                val      = (it["value"] + payload) if append else payload
                modified = self._inject(entry["raw"], it, val)
                self._rate_gate()
                self._count_sent()
                t0       = time.time()
                err_note = None
                try:
                    resp_obj = self._cb.makeHttpRequest(entry["svc"], modified)
                    resp_b   = resp_obj.getResponse()
                except Exception as ex:
                    resp_b, err_note = None, str(ex)
                elapsed  = int((time.time() - t0) * 1000)
                resp_str = self._h.bytesToString(resp_b) if resp_b else ""
                req_str  = self._h.bytesToString(modified)
                ri       = self._h.analyzeResponse(resp_b) if resp_b else None
                status   = str(ri.getStatusCode()) if ri else "ERR"
                length   = str(len(resp_b)) if resp_b else "0"

                err_hits = sql_error_hits(resp_str, self._opt_generic)
                dbms     = ", ".join(sorted(set(d for d, _s in err_hits)))

                flags = []
                if err_hits:
                    flags.append("SQLERR")
                if status == "ERR":
                    flags.append("NO-RESP")
                elif status[:1] == "5":
                    flags.append(status)
                want = payload_sleep_secs(payload, self._sleep_secs)
                if want and elapsed >= want * 1000 * self.SLOW_FLAG_PCT:
                    flags.append("SLOW")

                row = [rid, entry["path"], it["name"], where, payload, mode_lbl,
                       status, length, elapsed, fmt(len(err_hits)), dbms, " ".join(flags)]

                # Hold the response only when the row showed something - the same
                # set that reaches the Findings tab. The request is always kept:
                # it is small and Send to Repeater needs it.
                worth = bool(flags) or self._keep_all
                with self._lock:
                    self._stored[rid] = (req_str, resp_str if worth else None,
                                         entry["svc"], modified)
                    if worth:
                        self._kept += len(resp_str)
                    self._rows.append(row)
                    self._pending.append(row)
                    self._done += 1

                # Feed the Findings tab
                self._evaluate(entry, it, where, payload, status, length, elapsed,
                               err_hits, req_str, resp_str, modified, append, err_note)
            except Exception as ex:
                print("[SQLi Tester v4] Request error: %s" % ex)
                with self._lock:
                    self._done += 1

    def _scan_done(self):
        self._drain()            # whatever the last tick did not get
        self._stop_drain()
        self._btn_start.setEnabled(True); self._btn_simple.setEnabled(True)
        self._btn_stop.setEnabled(False)
        with self._lock:
            done, total, kept = self._done, self._total, self._kept
            rows = len(self._rows)
        self._prog.setValue(100 if done >= total else
                            (int(done * 100.0 / total) if total else 100))
        skipped = max(0, total - done)
        self._prog.setString(
            "Done  -  %d/%d probes, %d requests sent, %d row(s)%s, %.1f MB kept"
            % (done, total, self._sent, rows,
               ", %d not run (stopped)" % skipped if skipped else "",
               kept / 1048576.0))

    # -----------------------------------------------------------------------
    # Results helpers
    # -----------------------------------------------------------------------
    def _show_pair(self, view_row):
        mr = self._res_table.convertRowIndexToModel(view_row)
        n  = self._res_model.getValueAt(mr, 0)
        if n is not None:
            pair = self._stored.get(int(str(n)))
            if pair:
                self._req_view.set_text(pair[0])
                self._resp_view.set_text(
                    pair[1] if pair[1] is not None else NOT_RETAINED)

    def _clear(self):
        self._res_model.setRowCount(0)
        with self._lock:
            self._rows = []; self._stored = {}
            self._pending = []; self._pend_hits = {}
            self._pend_cells = {}; self._pend_frows = []
            self._kept = 0
            self._done = 0; self._total = 0
        self._sent = 0
        self._req_view.set_text(""); self._resp_view.set_text("")
        self._prog.setValue(0); self._prog.setString("Idle")
        self._clear_findings()

    def _filter(self):
        """Rebuild the table from the authoritative row list.

        v2 rebuilt from self._rows while worker threads kept appending straight
        into the model, so one keystroke during a scan left duplicated rows,
        rows that did not match the search, and a row count that agreed with
        nothing. The query is stored for the drain, which applies it to every
        row that arrives afterwards, and the pending queue is dropped because
        the snapshot already contains those rows."""
        query = self._search.getText().strip().lower()
        self._query = query
        with self._lock:
            rows = list(self._rows)
            self._pending = []
        self._res_model.setRowCount(0)
        for row in rows:
            if not query or any(query in str(c).lower() for c in row):
                self._res_model.addRow(row)
        if not self._scan:
            with self._lock:
                done, total, kept = self._done, self._total, self._kept
            if total:
                self._prog.setString(self._progress_text(done, total, self._sent, kept))

    # -----------------------------------------------------------------------
    # ITab / IExtensionStateListener
    # -----------------------------------------------------------------------
    def getTabCaption(self):  return "SQLi Tester v4"
    def getUiComponent(self): return self._root

    def extensionUnloaded(self):
        self._scan = False
        try:
            self._stop_drain()
        except Exception:
            pass
        print("[SQLi Tester v4] Unloaded.")
