package circuit

// BuildOptions captures auxiliary inputs for circuit preparation.
type BuildOptions struct {
	ConfigFilePath      string
	SparkConfigFilePath string
	Evaluation          string
	R1CSFilePath        string
	R1CSURL             string
	PkPath              string
	VkPath              string
	PkURL               string
	VkURL               string
	OutputCcsPath       string
	SaveKeys            string
}

func (b BuildOptions) HasR1CSFile() bool {
	return b.R1CSFilePath != ""
}

func (b BuildOptions) HasR1CSURL() bool {
	return b.R1CSURL != ""
}

func (b BuildOptions) HasPkAndVkFromURL() bool {
	return b.PkURL != "" && b.VkURL != ""
}

func (b BuildOptions) HasPkAndVkFromPath() bool {
	return b.PkPath != "" && b.VkPath != ""
}

func (b BuildOptions) ShouldSaveKeys() bool {
	return b.SaveKeys != ""
}
