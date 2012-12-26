tools-pwhois
============

Usage: pwhois [opts] query

    pwhois utilizes the phpWhois project by Mark Jeftovic (http://www.phpwhois.org) and primarily
        wraps that library in a cli which will give specific information from the query.

    OPTIONS
        -h          This usage information
        -c   dir    Caches results in the given directory for the cache timeframe
        -cd  days   The number of days to cache results for (will not re-lookup), default: 14 days
        -cc  days   The number of days to keep cache results for.  Defaults to -cd * 10, ignored if <= 0

        -o          Comma separated list of fields to retrieve, defaults to all unless specified, possible values:
                       inetnum          Retrieves the network range responsible
                       cidr             Retrieves the CIDR registered range responsible
                       abuse-email      Retrieves the abuse contact email address
                       country          Retrieves the country

        -d          Sets php directive display_errors to on
        -dR         Dumps the raw phpWhois result object for each query to stdout
        -dr         Dumps the raw whois response for each query to stdout

    EXAMPLE
        `pwhois -o cidr,abuse-email 58.221.58.179`
            > cidr:58.208.0.0/12
            > abuse-email:spam@jsinfo.net
