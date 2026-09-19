package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "gsk",
	Short: "CLI for interacting with Ghidra via HTTP API",
	Long: `A command-line interface for reverse engineering with Ghidra.
Connects to the GhidraHTTP plugin running in Ghidra's project window to
perform analysis, annotation, and code generation tasks on any program in
the open project.

Target a program with --program/-p (a project path such as /bin/ls, or a
unique file name), the GHIDRA_PROGRAM env var, or "program:" in .gsk.yaml.
Without it, commands use the program active in a CodeBrowser window, or the
only program the server has opened. Pass --all to run a command against
every open program.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .gsk.yaml)")
	rootCmd.PersistentFlags().String("server", "localhost:8080", "Ghidra server address")
	rootCmd.PersistentFlags().StringP("program", "p", "", "Project path of the program to operate on (default: active in Ghidra)")
	rootCmd.PersistentFlags().Bool("all", false, "Run the command against every open program")

	viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
	viper.BindPFlag("program", rootCmd.PersistentFlags().Lookup("program"))
	viper.BindPFlag("all", rootCmd.PersistentFlags().Lookup("all"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".gsk")
	}

	viper.SetEnvPrefix("GHIDRA")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func getGhidraServer() string {
	return viper.GetString("server")
}

func getGhidraProgram() string {
	return viper.GetString("program")
}

func getAllPrograms() bool {
	return viper.GetBool("all")
}
