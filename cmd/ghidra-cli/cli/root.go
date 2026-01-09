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
Connects to GhidraMCP plugin running in Ghidra to perform analysis,
annotation, and code generation tasks.`,
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
	
	viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
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