package common

import (
	"github.com/urfave/cli/v2"
)

// BuildOps contains all the configuration options for building and verifying circuits
type BuildOps struct {
	// Config file path
	ConfigFilePath string

	// R1CS file options
	R1csFilePath string
	R1csUrl      string

	// Proving and Verifying key options
	PkPath string
	VkPath string
	PkUrl  string
	VkUrl  string

	// Output options
	OutputCcsPath string
	SaveKeys      string
}

// NewBuildOpsFromContext creates a BuildOps struct from CLI context
func NewBuildOpsFromContext(c *cli.Context) *BuildOps {
	return &BuildOps{
		ConfigFilePath: c.String("config"),
		R1csFilePath:   c.String("r1cs"),
		R1csUrl:        c.String("r1cs_url"),
		PkPath:         c.String("pk"),
		VkPath:         c.String("vk"),
		PkUrl:          c.String("pk_url"),
		VkUrl:          c.String("vk_url"),
		OutputCcsPath:  c.String("ccs"),
		SaveKeys:       c.String("saveKeys"),
	}
}

func (b *BuildOps) HasR1csFile() bool {
	return b.R1csFilePath != ""
}

func (b *BuildOps) HasR1csUrl() bool {
	return b.R1csUrl != ""
}

func (b *BuildOps) HasPkAndVkFromUrl() bool {
	return b.PkUrl != "" && b.VkUrl != ""
}

func (b *BuildOps) HasPkAndVkFromPath() bool {
	return b.PkPath != "" && b.VkPath != ""
}

func (b *BuildOps) HasConfigFile() bool {
	return b.ConfigFilePath != ""
}

func (b *BuildOps) ShouldSaveKeys() bool {
	return b.SaveKeys != ""
}
