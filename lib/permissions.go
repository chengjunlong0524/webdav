package lib

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

type Rule struct {
	Permissions Permissions
	Path        string
	Regex       *regexp.Regexp
	FileAllowed Permissions
}

func (r *Rule) ToString() string {
	var ret string

	ret = ""
	if r.Path != "" {
		ret += r.Path
	} else if r.Regex != nil {
		ret += r.Regex.String()
	}

	ret = ret + " " + r.Permissions.ToString() + "-" + r.FileAllowed.ToString()
	return ret
}

func (r *Rule) Validate() error {
	if r.Regex == nil && r.Path == "" {
		return errors.New("invalid rule: must either define a path of a regex")
	}

	if r.Regex != nil && r.Path != "" {
		return errors.New("invalid rule: cannot define both regex and path")
	}

	return nil
}

// Matches checks if [Rule] matches the given path.
func (r *Rule) Matches(path string) bool {
	if r.Regex != nil {
		return r.Regex.MatchString(path)
	}

	return strings.HasPrefix(path, r.Path)
}

type RulesBehavior string

const (
	RulesOverwrite RulesBehavior = "overwrite"
	RulesAppend    RulesBehavior = "append"
)

type UserPermissions struct {
	Directory     string
	Permissions   Permissions
	FileAllowed   Permissions
	Rules         []*Rule
	RulesBehavior RulesBehavior
}

// Allowed checks if the user has permission to access a file
func (p UserPermissions) AllowedFile(r *request, fileExists func(string) bool) bool {
	var Paths []string
	for i := 0; i < len(p.Rules); i++ {
		Paths = append(Paths, p.Rules[i].ToString())
	}
	zap.L().Debug("AllowedFile", zap.String("Directory", p.Directory+" "+p.Permissions.ToString()+"-"+p.FileAllowed.ToString()))
	zap.L().Debug("AllowedFile", zap.String("Rules", strings.Join(Paths, "; ")))

	for i := len(p.Rules) - 1; i >= 0; i-- {
		if p.Rules[i].Matches(r.path) {
			if !p.Rules[i].FileAllowed.Allowed(r, fileExists) {
				zap.L().Info("AllowedFile " + r.path + " not allowed in Rules " + p.Rules[i].ToString())
				return false
			}

			zap.L().Info("AllowedFile " + r.path + " allowed in Rules " + p.Rules[i].ToString())
			return true
		}
	}

	stat := p.FileAllowed.Allowed(r, fileExists)
	if !stat {
		zap.L().Info("AllowedFile " + r.path + " not allowed in Permissions " + p.Directory + " " + p.Permissions.ToString() + "-" + p.FileAllowed.ToString())
		return false
	}

	zap.L().Info("AllowedFile " + r.path + " allowed in Permissions " + p.Directory + " " + p.Permissions.ToString() + "-" + p.FileAllowed.ToString())
	return stat
}

// Allowed checks if the user has permission to access a directory/file
func (p UserPermissions) Allowed(r *request, fileExists func(string) bool) bool {

	var Paths []string
	for i := 0; i < len(p.Rules); i++ {
		Paths = append(Paths, p.Rules[i].ToString())
	}

	zap.L().Debug("Allowed", zap.String("Directory", p.Directory+" "+p.Permissions.ToString()+"-"+p.FileAllowed.ToString()))
	zap.L().Debug("Allowed", zap.String("Rules", strings.Join(Paths, "; ")))

	// For COPY and MOVE requests, we first check the permissions for the destination
	// path. As soon as a rule matches and does not allow the operation at the destination,
	// we fail immediately. If no rule matches, we check the global permissions.
	if r.method == "COPY" || r.method == "MOVE" {
		dst := r.destination
		ruleMatched := false

		for i := len(p.Rules) - 1; i >= 0; i-- {
			if p.Rules[i].Matches(dst) {
				ruleMatched = true
				if !p.Rules[i].Permissions.AllowedDestination(r, fileExists) {
					zap.L().Info("Allowed COPY|MOVE " + dst + " not allowed in Rules " + p.Rules[i].ToString())
					return false
				}

				// Only check the first rule that matches, similarly to the source rules.
				zap.L().Info("Allowed COPY|MOVE " + dst + " allowed in Rules " + p.Rules[i].ToString())
				break
			}
		}

		if !ruleMatched && !p.Permissions.AllowedDestination(r, fileExists) {
			zap.L().Info("Allowed COPY|MOVE " + dst + " not allowed in Permissions " + p.Directory + " " + p.Permissions.ToString())
			return false
		}
	}

	// Go through rules beginning from the last one, and check the permissions at
	// the source. The first matched rule returns.
	for i := len(p.Rules) - 1; i >= 0; i-- {
		if p.Rules[i].Matches(r.path) {
			//zap.L().Debug("Allowed COPY|MOVE " + r.path + " not allowed in Rules " + p.Rules[i].ToString())
			//return p.Rules[i].Permissions.Allowed(r, fileExists)

			if !p.Rules[i].Permissions.Allowed(r, fileExists) {
				zap.L().Info("Allowed " + r.path + " not allowed in Rules " + p.Rules[i].ToString())
				return false
			}

			zap.L().Info("Allowed " + r.path + " allowed in Rules " + p.Rules[i].ToString())
			return true
		}
	}

	stat := p.Permissions.Allowed(r, fileExists)
	if !stat {
		zap.L().Info("Allowed " + r.path + " not allowed in Permissions " + p.Directory + " " + p.Permissions.ToString() + "-" + p.FileAllowed.ToString())
	}

	zap.L().Info("Allowed " + r.path + " allowed in Permissions " + p.Directory + " " + p.Permissions.ToString() + "-" + p.FileAllowed.ToString())
	return p.Permissions.Allowed(r, fileExists)
}

func (p *UserPermissions) Validate() error {
	var err error

	p.Directory, err = filepath.Abs(p.Directory)
	if err != nil {
		return fmt.Errorf("invalid permissions: %w", err)
	}

	for _, r := range p.Rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("invalid permissions: %w", err)
		}
	}

	switch p.RulesBehavior {
	case RulesAppend, RulesOverwrite:
		// Good to go
	default:
		return fmt.Errorf("invalid rule behavior: %s", p.RulesBehavior)
	}

	return nil
}

type Permissions struct {
	Create bool
	Read   bool
	Update bool
	Delete bool
}

func (p *Permissions) ToString() string {
	var ret string

	//ret = "CRUD="
	if p.Create {
		ret += "C"
	} else {
		ret += "X"
	}

	if p.Read {
		ret += "R"
	} else {
		ret += "X"
	}

	if p.Update {
		ret += "U"
	} else {
		ret += "X"
	}

	if p.Delete {
		ret += "D"
	} else {
		ret += "X"
	}

	return ret
}

func (p *Permissions) UnmarshalText(data []byte) error {
	text := strings.ToLower(string(data))
	if text == "none" {
		return nil
	}

	for _, c := range text {
		switch c {
		case 'c':
			p.Create = true
		case 'r':
			p.Read = true
		case 'u':
			p.Update = true
		case 'd':
			p.Delete = true
		default:
			return fmt.Errorf("invalid permission: %q", c)
		}
	}

	return nil
}

// Allowed returns whether this permission set has permissions to execute this
// request in the source directory. This applies to all requests with all methods.
func (p Permissions) Allowed(r *request, fileExists func(string) bool) bool {
	switch r.method {
	case "GET", "HEAD", "OPTIONS", "POST", "PROPFIND":
		// Note: POST backend implementation just returns the same thing as GET.
		return p.Read
	case "MKCOL":
		return p.Create
	case "PROPPATCH":
		return p.Update
	case "PUT":
		if fileExists(r.path) {
			return p.Update
		} else {
			return p.Create
		}
	case "COPY":
		return p.Read
	case "MOVE":
		return p.Read && p.Delete
	case "DELETE":
		return p.Delete
	case "LOCK", "UNLOCK":
		return p.Create || p.Read || p.Update || p.Delete
	default:
		return false
	}
}

// AllowedDestination returns whether this permissions set has permissions to execute this
// request in the destination directory. This only applies for COPY and MOVE requests.
func (p Permissions) AllowedDestination(r *request, fileExists func(string) bool) bool {
	switch r.method {
	case "COPY", "MOVE":
		if fileExists(r.destination) {
			return p.Update
		} else {
			return p.Create
		}
	default:
		return false
	}
}
