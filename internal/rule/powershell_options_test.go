package rule

import (
	"reflect"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestPowerShellOptionPrefixes(t *testing.T) {
	for _, tc := range []struct{ name, minimum string }{
		{"help", "h"},
		{"login", "l"},
		{"noexit", "noe"},
		{"noprofile", "nop"},
		{"nologo", "nol"},
		{"noninteractive", "noni"},
		{"interactive", "i"},
		{"configurationname", "config"},
		{"custompipename", "cus"},
		{"command", "c"},
		{"windowstyle", "w"},
		{"file", "f"},
		{"outputformat", "o"},
		{"inputformat", "inp"},
		{"executionpolicy", "ex"},
		{"encodedcommand", "e"},
		{"encodedarguments", "encodeda"},
		{"settingsfile", "settings"},
		{"workingdirectory", "wo"},
	} {
		for n := len(tc.minimum); n <= len(tc.name); n++ {
			for _, flag := range []string{"-" + tc.name[:n], "-" + strings.ToUpper(tc.name[:n])} {
				if got := powerShellOption(flag); got != "-"+tc.name {
					t.Errorf("%s = %s, want -%s", flag, got, tc.name)
				}
			}
		}
	}
	for _, tc := range []struct{ flag, want string }{
		{"-ec", "-encodedcommand"},
		{"-ea", "-encodedarguments"},
		{"-ep", "-executionpolicy"},
		{"-cwa", "-commandwithargs"},
		{"-of", "-outputformat"},
		{"-if", "-inputformat"},
		{"-wd", "-workingdirectory"},
		{"-?", "-help"},
		{"-ex:Bypass", "-executionpolicy"},
		{"-commandwitharg", "-commandwitharg"},
		{"-conf", "-conf"},
		{"-no", "-no"},
		{"-v", "-v"},
		{"-version", "-version"},
		{"-psconsolefile", "-psconsolefile"},
		{"encodedcommand", "encodedcommand"},
	} {
		if got := powerShellOption(tc.flag); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.flag, got, tc.want)
		}
	}
}

func TestAnalyzePowerShellOptionPrefixes(t *testing.T) {
	const script = "Write-Output marker"
	for _, tool := range []string{"Bash", "PowerShell"} {
		for _, option := range []struct{ name, value string }{
			{"encodedcommand", encodePowerShell(script)},
			{"command", "'" + script + "'"},
		} {
			for n := 1; n <= len(option.name); n++ {
				flag := "-" + option.name[:n]
				t.Run(tool+"/"+flag, func(t *testing.T) {
					a := analyzeEventShellCommandsDetailed(model.Event{
						ToolName: tool, Command: "pwsh " + flag + " " + option.value,
					})
					if a.err != nil || !a.usable || a.enforcementSafe {
						t.Fatalf("usable=%v safe=%v err=%v", a.usable, a.enforcementSafe, a.err)
					}
					if got := commandExecutables(a.commands); !reflect.DeepEqual(got, []string{"pwsh", "Write-Output"}) {
						t.Fatalf("commands = %q", got)
					}
				})
			}
		}
		t.Run(tool+"/launcher options", func(t *testing.T) {
			a := analyzeEventShellCommandsDetailed(model.Event{
				ToolName: tool, Command: "pwsh -NoP -NonI -ExecutionPol Bypass -Comm '" + script + "'",
			})
			if a.err != nil || !a.usable || a.enforcementSafe ||
				!reflect.DeepEqual(commandExecutables(a.commands), []string{"pwsh", "Write-Output"}) {
				t.Fatalf("unexpected analysis: %+v", a)
			}
		})
		for _, flag := range []string{"-commandx", "-encodx", "-no", "-conf"} {
			t.Run(tool+"/invalid/"+flag, func(t *testing.T) {
				a := analyzeEventShellCommandsDetailed(model.Event{
					ToolName: tool, Command: "pwsh " + flag + " '" + script + "'",
				})
				if a.err == nil || !strings.Contains(a.err.Error(), "unsupported PowerShell option") || a.enforcementSafe {
					t.Fatalf("unexpected analysis: %+v", a)
				}
				if got := commandExecutables(a.commands); !reflect.DeepEqual(got, []string{"pwsh"}) {
					t.Fatalf("commands = %q", got)
				}
			})
		}
	}
}
