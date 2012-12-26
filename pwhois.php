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
	$tblIncludeSearch = array(
		__DIR__.'/../../code/lib/phpwhois',
		__DIR__,
		getenv('PHPWHOIS_LIB_DIR'),
	);
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
		
		/** @var Whois		The whois.php resolver class */
		protected $objResolver = NULL;
		
		/** @var array 	The query parameters */
		protected $tblQuery;
		
		/** @var array	An array of possible output values */
		protected $tblOutputOptions = array();
		
		/** @var array	Chosen output fields */
		protected $tblOutputFields = array();
		
		/** @var int	If true, will dump the raw results object from phpWhois to stdout */
		protected $DumpRawResultsObject = false;
		
		/** @var int	If true, will dump the raw results from whois to stdout */
		protected $DumpRawResults = false;
		
		/** @var int	Default number of days to cache responses */
		protected $CacheDays = 14;
		
		/** @var int	Number of days before a cached file will be removed, defaults to $CacheDays * 10 if not specified at command line, ignored if 0 */
		protected $CacheCleanupDays = 0;
		
		/** @var string	Directory to cache responses in */
		protected $CacheDir = NULL;
		
		/** @var string Contains the raw results of the query */
		protected $RawResults = '';
		
		/** @var bool 	Set to true if the results have been read from cache (prevents re-writing to cache) */
		protected $ResultsReadFromCache = false;
		
		public static $VerbosityLevel = 0;
		
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
						break;
						
					case '-c':
						$j++;
						$this->SetCacheDir($param);
						break;
						
					case '-cd':
						$j++;
						if(!is_numeric($param))
							$this->ExitError("Invalid -cd parameter: {$param}, not numeric.");
						$this->CacheDays = (int)$param;

						if(!in_array('-cc', $argv))
							$this->CacheCleanupDays = $this->CacheDays * 10;
						break;

					case '-cc':
						$j++;
						if(!is_numeric($param))
							$this->ExitError("Invalid -cc parameter: {$param}, not numeric.");
						$this->CacheCleanupDays = (int)$param;
						break;
						
					case '-o':
						$j++;
						$this->tblOutputFields = array_unique(array_merge($this->tblOutputFields, explode(',', $param)));
						break;
					
					case '-d':		/* Checked for at very beginning */ 			break;
					case '-dR':		$this->DumpRawResultsObject = true;				break;
					case '-dr':		$this->DumpRawResults = true;					break;
						
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
			
			$this->ValidateOutputOptions();
			$this->Execute();
		}

		/**
		 * Sets the CacheDir and checks that it can create it or that it can write to a file in it
		 *
		 * @param $Directory
		 */
		protected function SetCacheDir($Directory) {
			$this->CacheDir = $Directory;
			if(is_dir($this->CacheDir)) {
				if(!is_writable($this->CacheDir))
					$this->ExitError("Cannot write to {$this->CacheDir}/.test_file, check permissions.");
			} else {
				if(!@mkdir($this->CacheDir, 0775, true))
					$this->ExitError("Cannot create cache directory \"{$this->CacheDir}\", check permissions.");
			}
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
			
			$tblInvalid = array();
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
					$this->tblOutputOptions[str_replace('_','-', $objMethod->name)] = str_replace(array('/**','*/'),'', $objMethod->getDocComment());
			}
			return true;
		}
		
		/*
		* Outputs usage information
		*/
		protected function Help() {
			$this->DetermineOutputOptions();

			$tblOutputClasses = array();
			foreach($this->tblOutputOptions as $Option => $Desc)
				$tblOutputClasses[] = sprintf("                       %-15.15s %s", $Option, $Desc);
			$OutputClasses = implode(PHP_EOL, $tblOutputClasses);

			echo <<<EOH
Usage: pwhois [opts] query

    pwhois utilizes the phpWhois project by Mark Jeftovic (http://www.phpwhois.org) and primarily
        wraps that library in a cli which will give specific information from the query.
        
    OPTIONS
        -h          This usage information
        -c   dir    Caches results in the given directory for the cache timeframe
        -cd  days   The number of days to cache results for (will not re-lookup), default: 14 days
        -cc  days   The number of days to keep cache results for.  Defaults to -cd * 10, ignored if <= 0
        
        -o          Comma separated list of fields to retrieve, defaults to all unless specified, possible values:
{$OutputClasses}

        -d          Sets php directive display_errors to on
        -dR         Dumps the raw phpWhois result object for each query to stdout
        -dr         Dumps the raw whois response for each query to stdout
        
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
				if(pwhois::$VerbosityLevel >= 1)
					echo "resolve: Resolving for query={$Query}".PHP_EOL;
					
				$tblResolved = $this->objResolver->Lookup($Query);
				
				$tblResolved = pwhois_utils::ExtrapolateData($tblResolved);

				if($this->DumpRawResultsObject)
					print_r($tblResolved);

				$tblResults = array();
				foreach($this->tblOutputOptions as $Field => $Description)
					$tblResults[$Field] = pwhois_output_parsers::$Field($tblResolved);
				
				$this->RawResults = implode(PHP_EOL, $tblResolved['rawdata']).PHP_EOL;
				return $tblResults;
			}
			if(pwhois::$VerbosityLevel >= 1)
				echo "cache: Results read from cache file={$CacheFilepath}".PHP_EOL;
			
			$CacheResults = file_get_contents($CacheFilepath);
			$tblResults = array();
			foreach(preg_split('/[\r\n]+/', $CacheResults) as $Line) {
				list($Key, $Value) = explode(':', $Line, 2);
				$tblResults[$Key] = $Value;
			}
			if(is_readable($RawCacheFilepath = $CacheFilepath.'_raw'))
				$this->RawResults = file_get_contents($RawCacheFilepath);
			else
				fwrite(STDERR, "Warning, could not read raw cache results file={$RawCacheFilepath}".PHP_EOL);
			
			$this->ResultsReadFromCache = true;
			
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
			if($this->CacheDir) {
				if(!preg_match(VALID_CIDR_PATTERN, $tblResults['cidr'])) {
					fwrite(STDERR, "Warning, could not cache results.  Output parameter cidr not a valid format (cidr={$tblResults['cidr']})".PHP_EOL);
					return false;
				}

				if(!is_writable($this->CacheDir)) {
					fwrite(STDERR, "Warning, cache dir ({$this->CacheDir}) is not writable, could not cache results".PHP_EOL);
					return false;
				}

				/* If we read our results from cache, do not re-write to cache */
				if(!$this->ResultsReadFromCache) {
					$Filepath = $this->CacheDir.'/'.str_replace('/', '_', $tblResults['cidr']);

					$tLines = array();
					foreach($this->tblOutputOptions as $Field => $Descrption)
						$tLines[] = $Field.':'.$tblResults[$Field];
					file_put_contents($Filepath, implode(PHP_EOL, $tLines).PHP_EOL);
					file_put_contents($Filepath.'_raw', $Raw);

					if(pwhois::$VerbosityLevel >= 1)
						echo "cache: Results written to cache file={$Filepath}".PHP_EOL;
				}
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
			
			if($this->CacheDir && is_writable($this->CacheDir) && $this->CacheDays > 0) {
				$ValidCacheTime = time() - ($this->CacheDays * 86400);
				$CleanCacheTime = time() - ($this->CacheCleanupDays * 86400);
				
				if(pwhois::$VerbosityLevel >= 1)
					echo "cache: Searching cache for {$Query}".PHP_EOL;

				/** @param $objFile DirectoryIterator */
				foreach(new DirectoryIterator($this->CacheDir) as $objFile) {
					if($objFile->isFile()) {
						$FileModifiedTime = $objFile->getMTime();
						if($FileModifiedTime > $ValidCacheTime && preg_match('/^(\d+\.\d+\.\d+\.\d+)_(\d+)$/', $objFile->getFilename(), $tMatches)) {
							if(pwhois_utils::MatchesCIDR($Query, $tMatches[1].'/'.$tMatches[2]))
								return $objFile->getPathname();
						}
						if($this->CacheCleanupDays > 0 && $FileModifiedTime < $CleanCacheTime) {
							if(pwhois::$VerbosityLevel >= 1)
								echo "cache: Cache file expired, deleted file=".$objFile->getPathname().PHP_EOL;
							unlink($objFile->getPathname());
						}
					}
				}
			}
			return false;
		}
		
		protected function Execute() {
			$this->objResolver = new Whois();

			foreach($this->tblQuery as $Query) {
				$tblResults = $this->Lookup($Query);
												
				if($this->DumpRawResults)
					echo implode(PHP_EOL, $this->RawResults);
				
				$this->CacheResults($tblResults, $this->RawResults);
					
				foreach($this->tblOutputFields as $Field) {
					if(count($this->tblQuery) > 1)
						echo $Query.'=';
					echo "{$Field}:{$tblResults[$Field]}".PHP_EOL;
				}
			}
		}
	}
	
	/**
	* Utility functions
	*/
	class pwhois_utils {
		
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
				if(pwhois::$VerbosityLevel >= 2)
					echo $FullRangeText.PHP_EOL;
				
				for($Length=32;$Length>0;$Length--) {
					$Mask = (pow(2, $Length)-1) << (32 - $Length);
					
					if(pwhois::$VerbosityLevel >= 2) {
						printf("Length=%-2u | Start=%-10u | End=%-10u | Mask=%-10u | Start & Mask = %-10u | End & Mask = %-10u | Match = %-10u".PHP_EOL,
							$Length, $StartRange, $EndRange, $Mask, 
							$StartRange & $Mask, 
							$EndRange & $Mask,
							($StartRange & $Mask) == ($EndRange & $Mask));
					}
					if(pwhois::$VerbosityLevel >= 3) {
						printf("   Start: %032b |  End: %032b".PHP_EOL, $StartRange, $EndRange);
						printf("    Mask: %032b | Mask: %032b".PHP_EOL, $Mask, $Mask);
						printf("          %032b |       %032b".PHP_EOL, $StartRange & $Mask, $EndRange & $Mask);
						echo PHP_EOL;
					}
					if(($StartRange & $Mask) == ($EndRange & $Mask))
						return $StartRangeText.'/'.$Length;
				}
			}
			return false;
		}

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
					if(preg_match($PatternSearch, $Datum) && preg_match($PatternCapture, $Datum, $tblMatches))
						return $tblMatches[0];
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
			$tblPossibleInfo = array(
				$tblResolved['rawdata'],
				$tblResolved['regrinfo']['tech']['remarks'],
				$tblResolved['regrinfo']['tech']['email'],
				$tblResolved['regrinfo']['admin']['remarks'],
				$tblResolved['regrinfo']['admin']['email'],
			);
			$tblPreferredPatterns = array(
				'/(anti-spam|antispam|spam)/' 	=> REGEX_EMAIL_PATTERN,
				'/(abuse)/'						=> REGEX_EMAIL_PATTERN,
			);
			$EmailAddress = pwhois_utils::SearchDataForPattern($tblPossibleInfo, $tblPreferredPatterns)
				?: $tblResolved['regrinfo']['tech']['email']
				?: $tblResolved['regrinfo']['admin']['email']
				?: 'unknown';
			
			return $EmailAddress;
		}
		
		/** Retrieves the country */
		static public function country($tblResolved) {
			$tblOwnerAddress = $tblResolved['regrinfo']['owner']['address'];
			return count($tblOwnerAddress) ? array_pop($tblOwnerAddress) : 'unknown';
		}

		/**
		 * @param string $name
		 * @param array $arguments
		 *
		 * @return mixed
		 */
		static public function __callStatic($name, $arguments) {
			$CallableName = str_replace('-','_', $name);
			if(is_callable(array('pwhois_output_parsers', $CallableName)))
				return self::$CallableName($arguments[0]);

			// This should never happen but is here to gracefully handle unexpected conditions
			fwrite(STDERR, "Unknown output field: ".str_replace('_','-',$name).", ignored.".PHP_EOL);
			return NULL;
		}
	}

	new pwhois();
