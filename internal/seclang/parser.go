// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/internal/io"
)

// maxIncludeRecursion is used to avoid DDOS by including files that include
const maxIncludeRecursion = 100

// Parser provides functions to evaluate (compile) SecLang directives
type Parser struct {
	options      *DirectiveOptions
	currentLine  int
	currentFile  string
	currentDir   string
	root         fs.FS
	includeCount int
}

// FromFile imports directives from a file
// It will return error if any directive fails to parse
// or the file does not exist.
// If the path contains a *, it will be expanded to all
// files in the directory matching the pattern
func (p *Parser) FromFile(profilePath string) error {
	originalDir := p.currentDir

fmt.Printf ("parser.go: 001 (%s)\n", p.currentDir)

	var files []string
fmt.Println ("parser.go: 002")
	if strings.Contains(profilePath, "*") {
fmt.Println ("parser.go: 003")
		var err error
		files, err = fs.Glob(p.root, profilePath)
fmt.Println ("parser.go: 004")
		if err != nil {
fmt.Println ("parser.go: 004 err")
			return fmt.Errorf("failed to glob: %s", err.Error())
		}
fmt.Println ("parser.go: 005")
	} else {
fmt.Println ("parser.go: 006")
		files = append(files, profilePath)
fmt.Println ("parser.go: 007")
	}
fmt.Println ("parser.go: 008")
	for _, profilePath := range files {
fmt.Printf ("parser.go: 009 :%s:", profilePath)
		profilePath = strings.TrimSpace(profilePath)
fmt.Println ("parser.go: 010")
		if !strings.HasPrefix(profilePath, "/") {
			profilePath = filepath.Join(p.currentDir, profilePath)
		}
fmt.Println ("parser.go: 011")
		p.currentFile = profilePath
		lastDir := p.currentDir
		p.currentDir = filepath.Dir(profilePath)
fmt.Println ("parser.go: 012")
		file, err := fs.ReadFile(p.root, profilePath)
fmt.Println ("parser.go: 013")
		if err != nil {
fmt.Println ("parser.go: 014")
			// we don't use defer for this as tinygo does not seem to like it
			p.currentDir = originalDir
			p.currentFile = ""
			return fmt.Errorf("failed to readfile: %s", err.Error())
		}
fmt.Println ("parser.go: 015")

		err = p.FromString(string(file))
fmt.Println ("parser.go: 016")
		if err != nil {
fmt.Println ("parser.go: 017")
			// we don't use defer for this as tinygo does not seem to like it
			p.currentDir = originalDir
			p.currentFile = ""
			return fmt.Errorf("failed to parse string: %s", err.Error())
		}
fmt.Println ("parser.go: 018")
		// restore the lastDir post processing all includes
		p.currentDir = lastDir
	}
fmt.Println ("parser.go: 019")
	// we don't use defer for this as tinygo does not seem to like it
	p.currentDir = originalDir
	p.currentFile = ""

fmt.Println ("parser.go: OUT")
	return nil
}

// FromString imports directives from a string
// It will return error if any directive fails to parse
// or arguments are invalid
func (p *Parser) FromString(data string) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var linebuffer strings.Builder
	inBackticks := false
	for scanner.Scan() {
		p.currentLine++
		line := strings.TrimSpace(scanner.Text())
		lineLen := len(line)
		if lineLen == 0 {
			continue
		}
		// As a first step, the parser has to ignore all the comments (lines starting with "#") in any circumstances.
		if line[0] == '#' {
			continue
		}

		// Looks for a line like "SecDataset test `". The backtick starts an action list.
		// The list will be closed only with a single "`" line.
		if !inBackticks && line[lineLen-1] == '`' {
			inBackticks = true
		} else if inBackticks && line[0] == '`' {
			inBackticks = false
		}

		if inBackticks {
			linebuffer.WriteString(line)
			linebuffer.WriteString("\n")
			continue
		}

		// Check if line ends with \
		if line[lineLen-1] == '\\' {
			linebuffer.WriteString(strings.TrimSuffix(line, "\\"))
		} else {
			linebuffer.WriteString(line)
			err := p.evaluateLine(linebuffer.String())
			if err != nil {
				return err
			}
			linebuffer.Reset()
		}
	}
	if inBackticks {
		return errors.New("backticks left open")
	}
	return nil
}

func (p *Parser) evaluateLine(l string) error {
	if l == "" || l[0] == '#' {
		panic("invalid line")
	}
	// first we get the directive
	dir, opts, _ := strings.Cut(l, " ")

	p.options.WAF.Logger.Debug().Str("line", l).Msg("Parsing directive")
	directive := strings.ToLower(dir)

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"' {
		opts = strings.Trim(opts, `"`)
	}
	if directive == "include" {
		// this is a special hardcoded case
		// we cannot add it as a directive type because there are recursion issues
		// note a user might still include another file that includes the original file
		// generating a DDOS attack
		if p.includeCount >= maxIncludeRecursion {
			return p.log(fmt.Sprintf("cannot include more than %d files", maxIncludeRecursion))
		}
		p.includeCount++
		return p.FromFile(opts)
	}
	d, ok := directivesMap[directive]
	if !ok || d == nil {
		return p.log(fmt.Sprintf("unknown directive %q", directive))
	}

	p.options.Raw = l
	p.options.Opts = opts
	p.options.Parser.LastLine = p.currentLine
	p.options.Parser.ConfigFile = p.currentFile
	p.options.Parser.ConfigDir = p.currentDir
	p.options.Parser.Root = p.root
	if environment.HasAccessToFS {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		p.options.Parser.WorkingDir = wd
	}

	if err := d(p.options); err != nil {
		return fmt.Errorf("failed to compile the directive %q: %w", directive, err)
	}

	return nil
}

func (p *Parser) log(msg string) error {
	p.options.WAF.Logger.Error().Int("line", p.currentLine).Msg(msg)
	return errors.New(msg)
}

// SetRoot sets the root of the filesystem for resolving paths. If not set, the OS's
// filesystem is used. Some use cases for setting a root are
//
// - os.DirFS to set a path to resolve relative paths from.
// - embed.FS to read rules from an embedded filesystem.
// - zip.Reader to read rules from a zip file.
func (p *Parser) SetRoot(root fs.FS) {
	p.root = root
}

// NewParser creates a new parser from a WAF instance
// Rules and settings will be inserted into the WAF
// rule container (RuleGroup).
func NewParser(waf *corazawaf.WAF) *Parser {
	p := &Parser{
		options: &DirectiveOptions{
			WAF:      waf,
			Datasets: make(map[string][]string),
		},
		root: io.OSFS{},
	}
	return p
}

type ParserConfig struct {
	DisabledRuleActions         []string
	DisabledRuleOperators       []string
	RuleDefaultActions          []string
	HasRuleDefaultActions       bool
	IgnoreRuleCompilationErrors bool
	LastLine                    int
	ConfigFile                  string
	ConfigDir                   string
	Root                        fs.FS
	WorkingDir                  string
}
