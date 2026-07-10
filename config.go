package go_i2cp

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// configRegex is used to parse configuration files
var configRegex = regexp.MustCompile("\\s*([\\w.]+)=\\s*(.+)\\s*;\\s*")

// ParseConfig parses a configuration file and calls the callback for each key-value pair
func ParseConfig(s string, cb func(string, string)) {
	file, err := os.Open(s)
	if err != nil {
		if !strings.Contains(err.Error(), "no such file") {
			Error("%s", err.Error())
		}
		return
	}
	defer file.Close()
	Debug("Parsing config file '%s'", s)
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		line := scan.Text()
		groups := configRegex.FindStringSubmatch(line)
		if len(groups) != 3 {
			continue
		}
		cb(groups[1], groups[2])
	}
	if err := scan.Err(); err != nil {
		Error("reading input from %s config %s", s, err.Error())
	}
}
