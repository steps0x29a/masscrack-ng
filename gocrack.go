package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
)

// Custom command line flag type allowing multiple instances of the same flag
type arrayFlags []string

// Implement Set method on arrayFlags type (flag.Value)
func (arrayFlag *arrayFlags) Set(value string) error {
	*arrayFlag = append(*arrayFlag, value)
	return nil
}

// Implement String method on arrayFlags type (flag.Value)
func (arrayFlag *arrayFlags) String() string {
	return fmt.Sprintf("Array Flag with length %d", len(*arrayFlag))
}

// A custom struct type that wraps all command line arguments in a single
// object, thus making it easier to pass it around if needed
type commandline struct {
	input     string
	wordlists arrayFlags
	verbose   bool
}

// Encapsulates all the result fields that are interesting to us.
type result struct {
	// The BSSID of a cracked WiFi network
	bssid string
	// The ESSID of a cracked WiFi network
	essid string
	// The cracked passphrase
	passphrase string
	// The name of the wordlist the password was found in
	wordlist string
}

// Makes sure that all required commandline arguments are present and make sense/are valid
func testCommandline(args commandline) {
	if args.input == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if !fileExists(args.input) {
		log.Fatalf("Input directory does not exist: %s\n", args.input)
	}
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// input file does not exist
		return false
	}
	return true
}

// Retrieves all files from a given directory, returning them as an array
// of os.FileInfo items.
// A file must be named like this in order to be picked up by the function:
//   <Some-ESSID>_<BSSID>.pcap
// Will exit the program if an error occurs.
func getFiles(path string) []os.FileInfo {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatalf("Unable to process handshakes directory '%s': %s", path, err)
	}

	f := []os.FileInfo{}
	var re = regexp.MustCompile(`(?m).+?_[0-9a-fA-F]{12}\.pcap`)

	// Filter them pcaps
	for _, file := range files {
		// Build coresponding .key filename
		keyFile := strings.Replace(file.Name(), ".pcap", ".key", 1)
		keyFilePath := filepath.Join(path, keyFile)
		if re.MatchString(file.Name()) && !fileExists(keyFilePath) {
			f = append(f, file)
		}
	}

	return f
}

func getInputFile(base string, info os.FileInfo) string {
	return filepath.Join(base, info.Name())
}

func parseCommandLine() commandline {
	directoryPtr := flag.String("input", "", "Path to a directory containg handshake files")
	var wordListFlags arrayFlags

	flag.Var(&wordListFlags, "wordlist", "A wordlist path")

	verbosePtr := flag.Bool("verbose", false, "Be verbose")

	flag.Parse()

	args := commandline{
		input:     *directoryPtr,
		wordlists: wordListFlags,
		verbose:   *verbosePtr,
	}

	testCommandline(args)

	return args
}

func parseFilename(filename string) (essid string, bssid string) {
	// Filename is supposed to be <ESSID>_<BSSID>.pcap
	split := strings.Split(strings.Replace(filename, ".pcap", "", 1), "_")
	if len(split) != 2 {
		log.Fatal("Invalid filename detected")
	}

	return split[0], fmtBSSID(split[1])
}

func getKeyFilePath(base string, info os.FileInfo) string {
	return filepath.Join(base, strings.Replace(info.Name(), ".pcap", ".key", 1))
}

func banner() {
	fmt.Printf("\n\n")
	fmt.Printf("  %s\n", " ██████╗  ██████╗  ██████╗██████╗  █████╗  ██████╗██╗  ██╗")
	fmt.Printf("  %s\n", "██╔════╝ ██╔═══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝")
	fmt.Printf("  %s\n", "██║  ███╗██║   ██║██║     ██████╔╝███████║██║     █████╔╝ ")
	fmt.Printf("  %s\n", "██║   ██║██║   ██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ")
	fmt.Printf("  %s\n", "╚██████╔╝╚██████╔╝╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗")
	fmt.Printf("  %s\n", " ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝")
	fmt.Printf("\n")
	fmt.Printf("%s%s%s\n\n", "                Coded with ", "🖤", " by steps0x29a")
	fmt.Printf("%s\n\n", aurora.BgRed(aurora.White("Remember: don't be evil, this is for educational purposes only!")))
}

//aurora.Red("❤"),

func countLines(filepath string) int {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Unable to access wordlist file '%s': '%s'", filepath, err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	var count int = 0
	for scanner.Scan() {
		count++
	}

	return count
}

func fmtBSSID(rawBSSID string) string {
	var buffer bytes.Buffer
	last := len(rawBSSID) - 1
	for i, char := range rawBSSID {
		buffer.WriteRune(char)
		if i%2 == 1 && i != last {
			buffer.WriteRune(':')
		}
	}
	return buffer.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func findLongestESSID(list []os.FileInfo) int {
	var longest int = 0
	for _, file := range list {
		essid, _ := parseFilename(file.Name())
		longest = max(longest, len(essid))
	}

	return longest
}

func getKeyFromOutput(output string) string {
	begin := strings.Index(output, "[") + 2
	end := strings.LastIndex(output, "]") - 1
	if end <= begin {
		return "<unknown>"
	}
	return output[begin:end]
}

func fixedLengthString(length int, str string) string {
	verb := fmt.Sprintf("%%%-d.%ds", length, length)
	return fmt.Sprintf(verb, str)
}

func countPasswords(wordlists []string) int {
	var passwordCount int = 0

	for _, wordlist := range wordlists {
		passwordCount += countLines(wordlist)
	}

	return passwordCount
}

func aircrack(bssid, essid, keyfile, wordlist, target string, file os.FileInfo) string {
	var cmdline = []string{"-q", "-a2", "-b", bssid, "-l", keyfile, "-e", essid, "-w", wordlist, target}
	cmd := exec.Command("aircrack-ng", cmdline...)
	data, err := cmd.Output()
	if err != nil {
		fmt.Printf("\nError processing %s: %s\n", file.Name(), err)
		return ""
	}
	return string(data)
}

func report(results []result) {
	if len(results) == 0 {
		fmt.Printf("\n😭 %s 😭\n", aurora.Red("Sorry, no passphrase could be cracked"))
	} else {
		fmt.Printf("\n🤩 %s 🤩\n\n", aurora.Green("Success! I've got some results!"))
		for _, result := range results {
			fmt.Printf("%s (%s) -> %s (from %s)\n", result.essid, result.bssid, aurora.BgGreen(aurora.White(aurora.Bold(result.passphrase))), result.wordlist)
		}
	}
}

func main() {

	args := parseCommandLine()

	if args.verbose {
		banner()
	}

	files := getFiles(args.input)

	var essidMaxLen = findLongestESSID(files)

	results := []result{}
	passwordCount := countPasswords(args.wordlists)

	if args.verbose {
		fmt.Printf("Files to crack: %15d\n", len(files))
		fmt.Printf("Wordlists:      %15d\n", len(args.wordlists))
		fmt.Printf("Password count: %15d\n\n", passwordCount)
	}

	for _, file := range files {
		abs := getInputFile(args.input, file)
		essid, bssid := parseFilename(file.Name())
		if args.verbose {
			fmt.Printf("Attempting to crack %s (%s)...[", fixedLengthString(essidMaxLen, essid), bssid)
		}
		target := getKeyFilePath(args.input, file)

		var currentWordlistCount int = 0

		for _, wordlist := range args.wordlists {
			currentWordlistCount++

			s := aircrack(bssid, essid, target, wordlist, abs, file)

			if strings.Contains(s, "Passphrase not in dictionary") {
				if args.verbose {
					fmt.Printf("❌")
				}
			} else if strings.Contains(s, "KEY FOUND") {
				if args.verbose {
					fmt.Printf("🤩")
				}
				r := result{
					bssid:      bssid,
					essid:      essid,
					passphrase: getKeyFromOutput(s),
					wordlist:   wordlist,
				}
				results = append(results, r)
				break
			} else if strings.Contains(s, "Unsupported file format (not a pcap or IVs file)") {
				if args.verbose {
					fmt.Printf("⛔")
				}
			} else {
				if args.verbose {
					fmt.Printf("😭")
				}
			}

			if currentWordlistCount != len(args.wordlists) {
				if args.verbose {
					fmt.Printf("%s", "|")
				}
			}

		}

		if args.verbose {
			fmt.Println("]")
		}

	}

	report(results)
}
