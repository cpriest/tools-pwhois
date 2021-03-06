#!/usr/bin/php -ddisplay_startup_errors 1 -ddisplay_errors 1
<?php
	/*
	 * Version: Open Software License v. 2.1
	 *
	 * The contents of this file are subject to the Open Software License Version
	 * 2.1 (the "License"); you may not use this file except in compliance with
	 * the License. You may obtain a copy of the License at
	 * http://www.opensource.org/licenses/osl-2.1.php
	 *
	 * Software distributed under the License is distributed on an "AS IS" basis,
	 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
	 * for the specific language governing rights and limitations under the
	 * License.
	 *
	 * The Initial Developer of the Original Code is
	 * 		Clint Priest
	 *
	 * Portions created by the Initial Developer are Copyright (C) 2010-2013
	 * the Initial Developer. All Rights Reserved.
	 *
	 * Contributor(s):
	 *
	 *
	 * Possible Future Features:
	 * 	- Memcached support for large caches / frequent queries
	 * 	- Increased -o options
	 * 	- Normalized inetnum output format to x.x.x.x - x.x.x.x
	 */

	if(in_array('-d', $argv))
		ini_set('display_errors', 'on');

	/** Locate phpWhois library */
	$tblIncludeSearch = [
		__DIR__.'/../../code/lib/phpwhois',
		__DIR__,
		getenv('PHPWHOIS_LIB_DIR'),
	];
	foreach($tblIncludeSearch as $Directory) {
		if($Directory && file_exists($IncludeFilepath = $Directory.'/whois.main.php')) {
			include($IncludeFilepath);
			break;
		}
	}
	if(!class_exists('Whois', false)) {
		echo "Unable to locate phpWhois library, search path:".PHP_EOL;
		foreach($tblIncludeSearch as $Directory) {
			if($Directory)
				echo "   ".$Directory.PHP_EOL;
		}
		echo PHP_EOL."You may also define an environment variable PHPWHOIS_LIB_DIR to specify it's location.".PHP_EOL;
		exit(1);
	}



	define('REGEX_EMAIL_PATTERN', 	'/([\w\d\-\+\.]+)@((\[([0-9]{1,3}\.){3}[0-9]{1,3}\])|(([\w\-]+\.)+)([a-zA-Z]{2,4}))/');
	define('VALID_CIDR_PATTERN',	'/\d+\.\d+\.\d+\.\d+\/\d+/');
	define('VALID_IP_PATTERN',		'/\d+\.\d+\.\d+\.\d+/');

	/**
	* Main execution class
	*/
	class pwhois {

		const F_NONE					= 0;
		const F_TABULAR_OUTPUT 			= 1;
		const F_BATCH_OUTPUT 			= 2;
		const F_SHOW_PROGRESS			= 4;

		/** @var int 		Flags affecting operation */
		protected $Flags = self::F_NONE;

		/** @var Whois		The whois.php resolver class */
		protected $objResolver = NULL;

		/** @var array 	The query parameters */
		protected $tblQuery;

		/** @var array	An array of possible output values */
		protected $tblOutputOptions = [];

		/** @var array	Chosen output fields */
		protected $tblOutputFields = [];

		/** @var int	If true, will dump the raw results object from phpWhois to stdout */
		protected $DumpRawResultsObject = false;

		/** @var int	If true, will dump the raw results from whois to stdout */
		protected $DumpRawResults = false;

		/** @var bool   If true, will dump the downloaded/cached results of the ISO-3166 Country Codes document */
		protected $DumpCountryCodes = false;

		/** @var string Contains the raw results of the query */
		protected $RawResults = '';

		/** @var bool 	Set to true if the results have been read from cache (prevents re-writing to cache) */
		protected $ResultsReadFromCache = false;

		/** @var int    Defines the verbosity level used when displaying debug information */
		public static $VerbosityLevel = 0;

		/** @var int	Default number of days to cache responses */
		public static $CacheDays = 14;

		/** @var int	Number of days before a cached file will be removed, defaults to $CacheDays * 10 if not specified at command line, ignored if 0 */
		public static $CacheCleanupDays = 0;

		/** @var string	Directory to cache responses in */
		public static $CacheDir = '/var/cache/pwhois';

		/**
		* Parses and validates input parameters, then executes
		*/
		public function __construct() {
			global $argv;
			array_shift($argv);	/* drop first argument - script location */

			if(count($argv) == 0)
				$this->ExitHelp();

			for($j=0;$j<count($argv);$j++) {
				$arg = $argv[$j];
				$param = $argv[$j+1];

				switch($arg) {
					case '-h':
						$this->ExitHelp();
						break;

					case '-c':
						$j++;
						$this->SetCacheDir($param);
						break;

					case '-cd':
						$j++;
						if(!is_numeric($param))
							$this->ExitError("Invalid -cd parameter: {$param}, not numeric.");
						self::$CacheDays = (int)$param;

						if(!in_array('-cc', $argv))
							self::$CacheCleanupDays = self::$CacheDays * 10;
						break;

					case '-cc':
						$j++;
						if(!is_numeric($param))
							$this->ExitError("Invalid -cc parameter: {$param}, not numeric.");
						self::$CacheCleanupDays = (int)$param;
						break;

					case '-o':
						$j++;
						$this->tblOutputFields = array_unique(array_merge($this->tblOutputFields, explode(',', $param)));
						break;

					/** @noinspection PhpMissingBreakStatementInspection */
					case '-f':
						$j++;
						$this->InputFile = $param;
						if(!file_exists($this->InputFile))
							$this->ExitError("{$this->InputFile} does not exist.");
						if(!is_readable($this->InputFile))
							$this->ExitError("{$this->InputFile} is not readable (exists but cannot read -- permissions??).");
						break;

					case '-t':
						$this->Flags |= self::F_TABULAR_OUTPUT;
						break;

					case '-b':
						$this->Flags |= self::F_BATCH_OUTPUT;
						break;

					case '-p':
						$this->Flags |= self::F_SHOW_PROGRESS;
						break;

					case '-d':		/* Checked for at very beginning */ 			break;
					case '-dR':		$this->DumpRawResultsObject = true;				break;
					case '-dr':		$this->DumpRawResults = true;					break;
					case '-dcc':    $this->DumpCountryCodes = true;                 break;

					case '-v':
					case '-vv':
					case '-vvv':
					case '-vvvv':
						self::$VerbosityLevel = strlen($arg)-1;
						break;

					default:
						if($arg{0} == '-')
							$this->ExitError("Unknown option {$arg}");
						$this->tblQuery[] = $arg;
						break;
				}
			}

			if(!($this->Flags & self::F_BATCH_OUTPUT) && count($this->tblQuery) > 1 && exec('which column 2>/dev/null', $tOutput, $ExitCode))
				$this->Flags |= self::F_TABULAR_OUTPUT;


			if($this->Flags & self::F_TABULAR_OUTPUT && $this->Flags & self::F_BATCH_OUTPUT)
				$this->ExitError('-b and -t options cannot both be specified.');

			$this->ValidateOutputOptions();
			$this->SetCacheDir(self::$CacheDir);
			$this->Execute();
		}

		/**
		 * Sets the CacheDir and checks that it can create it or that it can write to a file in it
		 *
		 * @param $Directory
		 */
		protected function SetCacheDir($Directory) {
			if(is_dir($Directory)) {
				if(!is_writable($Directory))
					$this->ExitError("Cannot write to {$Directory}/.test_file, check permissions.");
			} else {
				if(!@mkdir($Directory, 0777, true))
					$this->ExitError("Cannot create cache directory \"{$Directory}\", check permissions.");
			}
			self::$CacheDir = $Directory;
		}

		/**
		 * Validates that the given -o parameters are available output options
		 *
		 * @return bool
		 */
		protected function ValidateOutputOptions() {
			$this->DetermineOutputOptions();

			if(count($this->tblOutputFields) == 0)
				$this->tblOutputFields = array_keys($this->tblOutputOptions);

			$tblInvalid = [];
			foreach($this->tblOutputFields as $Field) {
				if(!array_key_exists($Field, $this->tblOutputOptions))
					$tblInvalid[] = $Field;
			}
			if(count($tblInvalid))
				$this->ExitError("Unknown output field (-o): ".implode(', ', $tblInvalid));
			return true;
		}

		/**
		 * Scans the pwhois_output_parsers class to get a list of valid output options
		 *
		 * @return bool
		 */
		protected function DetermineOutputOptions() {
			if(count($this->tblOutputOptions) != 0)
				return true;

			$objMirror = new ReflectionClass('pwhois_output_parsers');
			foreach($objMirror->getMethods() as $objMethod) {
				if($objMethod->isPublic() && $objMethod->getDocComment() && $objMethod->name != '__callStatic')
					$this->tblOutputOptions[str_replace('_','-', $objMethod->name)] = str_replace(['/**','*/'],'', $objMethod->getDocComment());
			}
			return true;
		}

		/*
		* Outputs usage information
		*/
		protected function Help() {
			$this->DetermineOutputOptions();

			$tblOutputClasses = [];
			foreach($this->tblOutputOptions as $Option => $Desc)
				$tblOutputClasses[] = sprintf("                       %-15.15s %s", $Option, $Desc);
			$OutputClasses = implode(PHP_EOL, $tblOutputClasses);

			echo <<<EOH
Usage: pwhois [opts] {query | -f <file>}

    pwhois utilizes the phpWhois project by Mark Jeftovic (http://www.phpwhois.org) and primarily
        wraps that library in a cli which will give specific information from the query.

    OPTIONS
        -h          This usage information
        -c   dir    Caches results in the given directory for the cache timeframe, default: /var/cache/pwhois
        -cd  days   The number of days to cache results for (will not re-lookup), default: 14 days
        -cc  days   The number of days to keep cache results for.  Defaults to -cd * 10, ignored if <= 0

        -f   <file> Reads lines from the file and runs the query on the first ip address on each line and outputs
                    the input line with the query results appended

        -o          Comma separated list of fields to retrieve, defaults to all unless specified, possible values:
{$OutputClasses}

		-p			Show progress of lookups
		-t			Output data in tabular format; separated by tabs.  If the linux column command is available, it will be used to pretty print the tabular data
					This defaults to true if there is more than one query and the column command is available
		-b			Output data in batch format, suitable for parsing

        -d          Sets php directive display_errors to on
        -dR         Dumps the raw phpWhois result object for each query to stdout
        -dr         Dumps the raw whois response for each query to stdout
        -dcc        Display Country Codes from ISO-3166

        * 2 Letter Country Code conversions will only occur if the ISO-3166 file can be downloaded and cached,
          cache timing follows -cd

    EXAMPLE
        `pwhois -o cidr,abuse-email 58.221.58.179`
            > cidr:58.208.0.0/12
            > abuse-email:spam@jsinfo.net

EOH;
		}

		/**
		* Emits the given error to stderr and then exits 1 with usage information
		*
		* @param string $Message
		*/
		protected function ExitError($Message) {
			fwrite(STDERR, $Message.PHP_EOL.PHP_EOL);
			$this->Help();
			exit(1);
		}

		/**
		* Emits usage information and exits 0
		*/
		protected function ExitHelp() {
			$this->Help();
			exit(0);
		}

		/**
		 * Queries information for the given $Query (ip address)
		 *
		 * @param string $Query
		 *
		 * @return array
		 */
		protected function Lookup($Query) {
			if(!($CacheFilepath = $this->FindCachedResults($Query))) {
				self::Debug(1, "resolve: Resolving for query={$Query}");

				$tblResolved = $this->objResolver->Lookup($Query);

				$tblResolved = pwhois_utils::ExtrapolateData($tblResolved);

				if($this->DumpRawResultsObject)
					print_r($tblResolved);

				$tblResults = [];
				foreach($this->tblOutputOptions as $Field => $Description)
					$tblResults[$Field] = pwhois_output_parsers::$Field($tblResolved);

				$this->RawResults = $tblResolved['rawdata'];
				$this->CacheResults($tblResults, $this->RawResults);

				return $tblResults;
			}
			self::Debug(1, "cache: Results read from cache file={$CacheFilepath}");

			$CacheResults = file_get_contents($CacheFilepath);
			$tblResults = [];
			foreach(preg_split('/[\r\n]+/', $CacheResults) as $Line) {
				list($Key, $Value) = explode(':', $Line, 2);
				$tblResults[$Key] = $Value;
			}
			if(is_readable($RawCacheFilepath = $CacheFilepath.'_raw'))
				$this->RawResults = explode(PHP_EOL, file_get_contents($RawCacheFilepath));
			else
				fwrite(STDERR, "Warning, could not read raw cache results file={$RawCacheFilepath}".PHP_EOL);

			return $tblResults;
		}

		/**
		* Caches the results to the cache directory
		*
		* @param array 	$tblResults		The parsed results of all -o options
		* @param string $Raw			The raw results of the whois query
		* @return bool
		*/
		protected function CacheResults($tblResults, $Raw) {
			if(self::$CacheDir) {
				if(!preg_match(VALID_CIDR_PATTERN, $tblResults['cidr'])) {
					fwrite(STDERR, "Warning, could not cache results.  Output parameter cidr not a valid format (cidr={$tblResults['cidr']})".PHP_EOL);
					return false;
				}

				if(!is_writable(self::$CacheDir)) {
					fwrite(STDERR, "Warning, cache dir (".self::$CacheDir.") is not writable, could not cache results".PHP_EOL);
					return false;
				}

				/* If we read our results from cache, do not re-write to cache */
				$Filepath = self::$CacheDir.'/'.str_replace('/', '_', $tblResults['cidr']);

				$tLines = [];
				foreach($this->tblOutputOptions as $Field => $Description)
					$tLines[] = $Field.':'.$tblResults[$Field];
				file_put_contents($Filepath, implode(PHP_EOL, $tLines).PHP_EOL);
				file_put_contents($Filepath.'_raw', implode(PHP_EOL, $Raw).PHP_EOL);

				self::Debug(1, "cache: Results written to cache file={$Filepath}");
			}
			return true;
		}

		/**
		 * Searches the cache directory for a valid cache file, returns the filepath if found
		 *
		 * @param string $Query
		 *
		 * @return bool
		 */
		protected function FindCachedResults($Query) {
			if(!preg_match(VALID_IP_PATTERN, $Query))
				return false;

			if(self::$CacheDir && is_writable(self::$CacheDir) && self::$CacheDays > 0) {
				$ValidCacheTime = time() - (self::$CacheDays * 86400);
				$CleanCacheTime = time() - (self::$CacheCleanupDays * 86400);

				self::Debug(1, "cache: Searching cache for {$Query}");

				/** @param $objFile DirectoryIterator */
				foreach(new DirectoryIterator(self::$CacheDir) as $objFile) {
					/** @var $objFile DirectoryIterator */
					if($objFile->isFile()) {
						$FileModifiedTime = $objFile->getMTime();
						if($FileModifiedTime > $ValidCacheTime && preg_match('/^(\d+\.\d+\.\d+\.\d+)_(\d+)$/', $objFile->getFilename(), $tMatches)) {
							if(pwhois_utils::MatchesCIDR($Query, $tMatches[1].'/'.$tMatches[2]))
								return $objFile->getPathname();
						}
						if(self::$CacheCleanupDays > 0 && $FileModifiedTime < $CleanCacheTime) {
							self::Debug(1, "cache: Cache file expired, deleted file=".$objFile->getPathname());
							unlink($objFile->getPathname());
						}
					}
				}
			}
			return false;
		}

		/**
		 * @return null|void
		 */
		protected function Execute() {
			$this->objResolver = new Whois();

			if($this->InputFile) {
				$this->ExecuteForFile();
				return;
			}
			$tblAllResults = [ ];
			$TotalQueries = count($this->tblQuery);
			$FL = strlen($TotalQueries);
			foreach($this->tblQuery as $Index => $Query) {
				if($this->Flags & self::F_SHOW_PROGRESS)
					printf("\r%100s\r%0{$FL}s/%0{$FL}s Looking up %s", '', $Index+1, $TotalQueries, $Query);
				$tblResults = $this->Lookup($Query);

				if($this->DumpRawResults)
					echo implode(PHP_EOL, $this->RawResults);

				$tblAllResults[$Query] = $tblResults;
			}
			if($this->Flags & self::F_SHOW_PROGRESS)
				echo "\r";

			echo str_repeat(' ', 100)."\r";

			if($this->Flags & self::F_TABULAR_OUTPUT)
				$this->OutputTabular($tblAllResults);
			else
				$this->OutputNormal($tblAllResults);
			return;
		}

		protected function ExecuteForFile() {
			$SeparationChar = NULL;
			$objFile = new SplFileObject($this->InputFile);
			$objFile->setFlags(SplFileObject::DROP_NEW_LINE | SplFileObject::SKIP_EMPTY | SplFileObject::READ_AHEAD);
			$tblOutputFields = array_flip($this->tblOutputFields);
			foreach($objFile as $Index => $Line) {
				if($Index == 0) {
					$tChars = array_intersect_key(count_chars($Line), array_flip([ord("\t"),ord(" "),ord(",")]));
					arsort($tChars, SORT_NATURAL);
					$SeparationChar = chr(array_keys($tChars)[0]);
				}
				if(preg_match('#\d+\.\d+\.\d+\.\d+#', $Line, $tMatches)) {
					$tblResults = $this->Lookup($tMatches[0]);

					echo $Line.$SeparationChar;
					$tblSelectedResults = array_intersect_key($tblResults, $tblOutputFields);
					$tOutput = [ ];
					foreach($tblSelectedResults as $Key => $Value)
						$tOutput[] = $Key.'='.$Value;
					echo implode(',', $tOutput).PHP_EOL;
				} else {
					echo implode($SeparationChar, [$Line, "Could not locate an ip address to query against"]);
				}
			}
		}

		/**
		 * @param array[] $tblAllResults	All results indexed by Query
		 */
		public function OutputNormal($tblAllResults) {
			$tLines = [ ];
			foreach($tblAllResults as $Query => $tblResults) {
				foreach($this->tblOutputFields as $Field) {
					$Line = '';
					if(count($this->tblQuery) > 1)
						$Line .= "{$Query}=";
					$Line .= "{$Field}:{$tblResults[$Field]}";
					$tLines[] = $Line;
				}
			}
			echo implode(PHP_EOL, $tLines).PHP_EOL;
		}

		/**
		 * @param array[] $tblAllResults	All results indexed by Query
		 */
		public function OutputTabular($tblAllResults) {
			$tLines = [ ];
			$tLines[] = "query\t".implode("\t", $this->tblOutputFields);
			$tblOutputFieldsAsKeys = array_flip($this->tblOutputFields);

			foreach($tblAllResults as $Query => $tblResults)
				$tLines[] = $Query."\t".implode("\t", array_values(array_intersect_key($tblResults, $tblOutputFieldsAsKeys)));

			$ColumnCmd = exec('/usr/bin/which column', $tOutput, $ExitCode);
			$Output = implode(PHP_EOL, $tLines).PHP_EOL;
			if($ExitCode == 0)
				passthru("echo '{$Output}' | {$ColumnCmd} -t -s '	'");
			else
				echo $Output;
		}
		/**
		 * Sends the given $Message out if the Verbosity Level >= $Level, may also specify message as first parameter,
		 *      in which case $Level is assumed to be 0 (always)
		 *
		 * @param mixed     $Level      The level at which $Message will be shown, level is determined by -v[vvvv]
		 * @param string    $Message    The message to be shown
		 */
		public static function Debug($Level, $Message=NULL) {
			if($Message === NULL) {
				$Message = $Level;
				$Level = 0;
			}
			if(self::$VerbosityLevel >= $Level)
				echo $Message.PHP_EOL;
		}
	}

	/**
	* Utility functions
	*/
	class pwhois_utils {
		/** @var string[]	An array of country names, indexed by two letter UPPER CASE country code  */
		static private $tblIso3661Conversions = NULL;

		/**
		 * Returns the ISO-3661 country name if a cache directory is available and $CountryCode is found
		 *
		 * @param string $CountryCode   The ISO-3661 country code to convert to a full name
		 *
		 * @return string   The full country name if file is available and match is found, otherwise input string
		 */
		static public function CountryCodeToCountryName($CountryCode) {
			if(is_null(self::$tblIso3661Conversions)) {
				if(!pwhois::$CacheDir)
					return $CountryCode;
				if(!is_readable($Iso3661Filepath = pwhois::$CacheDir.'/ISO-3661.txt') || time() > filemtime($Iso3661Filepath) + (pwhois::$CacheDays * 86400)) {
					if(file_exists($Iso3661Filepath) && !is_writable($Iso3661Filepath)) {
						pwhois::Debug(0, "Not able to write ISO-3661 file to cache file: ".$Iso3661Filepath);
						return $CountryCode;
					}
					pwhois::Debug(2, "Downloading ISO-3661 from http://www.iso.org");
					file_put_contents($Iso3661Filepath, file_get_contents('http://www.iso.org/iso/home/standards/country_codes/country_names_and_code_elements_txt.htm'));
				}
				if(!is_readable($Iso3661Filepath)) {
					pwhois::Debug(0, "Not able to read ISO-3661 file from: ".$Iso3661Filepath);
					return $CountryCode;
				}
				pwhois::Debug(2, "Reading ISO-3661 Data from: {$Iso3661Filepath}");
				foreach(preg_split('|\r\n|', file_get_contents($Iso3661Filepath)) as $Line) {
					list($Country, $Code) = explode(';', $Line, 2);
					if(strlen($Code) == 2)
						self::$tblIso3661Conversions[strtoupper($Code)] = ucwords(strtolower($Country));
				}
			}
			return self::$tblIso3661Conversions[strtoupper($CountryCode)] ?: $CountryCode;
		}

		/** Returns true if the given ip address matches the given $CIDR
		*
		* @param string $IpAddress
		* @param string $CIDR
		* @return bool
		*/
		static public function MatchesCIDR($IpAddress, $CIDR) {
			if(preg_match('/(\d+\.\d+\.\d+\.\d+)\/(\d+)/', $CIDR, $tMatches)) {
				/** @noinspection PhpUnusedLocalVariableInspection */
				list($x, $Network, $Length) = $tMatches;
				$Mask = (pow(2, $Length)-1) << (32 - $Length);
				$NetworkLong = ip2long($Network);
				$IpLong = ip2long($IpAddress);
				return ($NetworkLong & $Mask) == ($IpLong & $Mask);
			}
			return false;
		}

		/**
		* Extrapolates information from the resolved results and returns the extended resolve array
		*
		* @param array $tblResolved
		* @return array
		*/
		static public function ExtrapolateData($tblResolved) {
			$tblResolved['regrinfo']['network'] = self::ExtrapolateCIDR($tblResolved['regrinfo']['network']);
			return $tblResolved;
		}

		/**
		* Calculates the CIDR for the network(s)
		*
		* @param array $tblNetworks
		* @return array
		*/
		static public function ExtrapolateCIDR($tblNetworks) {
			if($tblNetworks['inetnum'])
				$tblNetworks['cidr'] = pwhois_utils::CalculateCIDR($tblNetworks['inetnum']);
			else if(is_array($tblNetworks)) {
				/* Calculate CIDR for each network */
				foreach($tblNetworks as &$tblNetwork) {
					if($tblNetwork['inetnum'])
						$tblNetwork['cidr'] = $tblNetwork['cidr'] ?: pwhois_utils::CalculateCIDR($tblNetwork['inetnum']);
					unset($tblNetwork);
				}
			}
			return $tblNetworks;
		}

		/**
		* Returns the tightest network by CIDR length and returns that network array
		*
		* @param array $tblNetworks
		* @return array
		*/
		static public function FindTightestNetwork($tblNetworks) {
			if($tblNetworks['inetnum'])
				return $tblNetworks;

			/* Find tightest CIDR */
			$tblTightestNetwork = NULL;
			$TightestNetworkLength = 0;

			foreach($tblNetworks as $tblNetwork) {
				if(preg_match('/\d+\.\d+\.\d+\.\d+\/(\d+)/', $tblNetwork['cidr'], $tblMatches)) {
					if(is_null($tblTightestNetwork) || $tblMatches[1] > $TightestNetworkLength) {
						$tblTightestNetwork = $tblNetwork;
						$TightestNetworkLength = $tblMatches[1];
					}
				}
			}
			return $tblTightestNetwork;
		}

		/**
		* Calculates the CIDR for the given x.x.x.x - x.x.x.x range
		*
		* @param string $NetInetNum
		*
		* @return string|bool
		*/
		static public function CalculateCIDR($NetInetNum) {
			if(preg_match('/(\d+\.?\d*\.?\d*\.?\d*)\/(\d+)/', $NetInetNum, $tblMatches)) {
				$tblOctets = explode('.', $tblMatches[1]);
				while(count($tblOctets) < 4)
					array_push($tblOctets, 0);
				$tblMatches[1] = implode('.', $tblOctets);
				return $tblMatches[1].'/'.$tblMatches[2];
			}
			if(preg_match('/(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)/', $NetInetNum, $tblMatches)) {
				list($FullRangeText, $StartRangeText, $EndRangeText) = $tblMatches;
				$StartRange = ip2long($StartRangeText);
				$EndRange = ip2long($EndRangeText);
				pwhois::Debug(2, "Finding CIDR Mask for: {$FullRangeText}");

				for($Length=32;$Length>0;$Length--) {
					$Mask = (pow(2, $Length)-1) << (32 - $Length);

					pwhois::Debug(3, sprintf("    Length=%-2u | Start=%-10u | End=%-10u | Mask=%-10u | Start & Mask = %-10u | End & Mask = %-10u | Match = %-10u",
												$Length, $StartRange, $EndRange, $Mask,
												$StartRange & $Mask,
												$EndRange & $Mask,
												($StartRange & $Mask) == ($EndRange & $Mask)));

					pwhois::Debug(4, sprintf("       Start: %032b |  End: %032b", $StartRange, $EndRange));
					pwhois::Debug(4, sprintf("        Mask: %032b | Mask: %032b", $Mask, $Mask));
					pwhois::Debug(4, sprintf("              %032b |       %032b", $StartRange & $Mask, $EndRange & $Mask));
					pwhois::Debug(4, '');

					if(($StartRange & $Mask) == ($EndRange & $Mask))
						return $StartRangeText.'/'.$Length;
				}
			}
			return false;
		}

		const CAPTURE_FULL = 0;
		const CAPTURE_FIRST = 1;
		const CAPTURE_SECOND = 2;
		/**
		* Searches the given array of data for data matching the pattern, if pattern patches
		* 	returns $1 if present or $0 otherwise
		*
		* @param array[string|array[]] 	$tblPossibleInfo	An array of information to search through
		* @param array					$tblPatterns		An array of $PatternSearch => $PatternCapture pairs
		*
		* @return string|bool
		*/
		static public function SearchDataForPattern($tblPossibleInfo, $tblPatterns) {
			foreach($tblPossibleInfo as $Datum) {
				if(is_array($Datum) && ($Result = self::SearchDataForPattern($Datum, $tblPatterns)))
					return $Result;
				foreach((array)$tblPatterns as $PatternSearch => $PatternCapture) {
					if(preg_match($PatternSearch, $Datum, $tblMatches)) {
						if(is_numeric($PatternCapture))
							return $tblMatches[$PatternCapture];
						if(preg_match($PatternCapture, $Datum, $tblMatches))
							return $tblMatches[0];
					}
				}
			}
			return false;
		}
	}

	/**
	* Output parsers
	*/
	class pwhois_output_parsers {

		/** Retrieves the network range responsible */
		static public function inetnum($tblResolved) {
			$tblTightestNetwork = pwhois_utils::FindTightestNetwork($tblResolved['regrinfo']['network']);
			return $tblTightestNetwork['inetnum'] ?: 'Unknown';
		}

		/** Retrieves the CIDR registered range responsible */
		static public function cidr($tblResolved) {
			$tblTightestNetwork = pwhois_utils::FindTightestNetwork($tblResolved['regrinfo']['network']);
			return $tblTightestNetwork['cidr'] ?: 'Unknown';
		}

		/** Retrieves the abuse contact email address */
		static public function abuse_email($tblResolved) {
			$tblPossibleInfo = [
				implode(PHP_EOL, $tblResolved['rawdata']),
				$tblResolved['regrinfo']['tech']['remarks'],
				$tblResolved['regrinfo']['tech']['email'],
				$tblResolved['regrinfo']['admin']['remarks'],
				$tblResolved['regrinfo']['admin']['email'],
			];
			$tblPreferredPatterns = [
				'/(anti-spam|antispam|spam)/i' 	=> REGEX_EMAIL_PATTERN,
				'/(abuse)/i'					=> REGEX_EMAIL_PATTERN,
			];
			return pwhois_utils::SearchDataForPattern($tblPossibleInfo, $tblPreferredPatterns)
				?: $tblResolved['regrinfo']['tech']['email']
				?: $tblResolved['regrinfo']['admin']['email']
				?: 'unknown';
		}

		/** Translates the country-code into the full country name by ISO-3661 standards */
		static public function country($tblResolved) {
			return pwhois_utils::CountryCodeToCountryName(self::country_code($tblResolved));
		}

		/** Retrieves the country-code */
		static public function country_code($tblResolved) {
			if(($tblOwnerAddress = self::FindOwnerAddress($tblResolved, ['owner', 'tech', 'abuse', 'network'])) !== false)
				return array_pop($tblOwnerAddress);

			$tblPossibleInfo = [
				implode(PHP_EOL, $tblResolved['rawdata']),
			];
			$tblPreferredPatterns = [
				'/country:\s*(.+)/i'    => pwhois_utils::CAPTURE_FIRST,
			];
			return pwhois_utils::SearchDataForPattern($tblPossibleInfo, $tblPreferredPatterns)
				?: 'unknown';
		}

		/**
		 * @param string $name
		 * @param array $arguments
		 *
		 * @return mixed
		 */
		static public function __callStatic($name, $arguments) {
			$CallableName = str_replace('-','_', $name);
			if(is_callable(['pwhois_output_parsers', $CallableName]))
				return self::$CallableName($arguments[0]);

			// This should never happen but is here to gracefully handle unexpected conditions
			fwrite(STDERR, "Unknown output field: ".str_replace('_','-',$name).", ignored.".PHP_EOL);
			return NULL;
		}

		/**
		 * @param array $tblResolved    The resolved data structure from phpwhois lib
		 * @param array $tblSegments    The ordered list of regrinfo segment to look for an address
		 *
		 * @return bool|array   Returns first address array found or false otherwise
		 */
		private static function FindOwnerAddress($tblResolved, $tblSegments) {
			foreach($tblSegments as $Segment) {
				if(is_array($tblOwnerAddress = $tblResolved['regrinfo'][$Segment]['address'])) {
					pwhois::Debug(5, "FindOwnerAddress(): returning {$Segment}address");
					return $tblOwnerAddress;
				}

				if($tblResolved['regrinfo'][$Segment][0]) {
					foreach($tblResolved['regrinfo'][$Segment] as $Index => $tInfo) {
						if(is_array($tInfo['address']) && count($tInfo['address'])) {
							pwhois::Debug(5, "FindOwnerAddress(): returning {$Segment}[{$Index}] address");
							return $tInfo['address'];
						}
					}
				}
			}
			return false;
		}
	}

	new pwhois();
