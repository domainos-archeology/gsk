{
  description = "gsk - a command line for interfacing with ghidra";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem
      (
        system:
        let
           pkgs = import nixpkgs { inherit system; };
        in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              # Go CLI tools
              go
              git
              gopls
              gotools
              golangci-lint

              # Java/Ghidra plugin development
              jdk21
              gradle
            ];

            shellHook = ''
              echo "Go version: $(go version)"
              echo "Java version: $(java -version 2>&1 | head -n 1)"
              echo "Gradle version: $(gradle --version 2>&1 | grep 'Gradle' | head -n 1)"
              echo ""
              echo "To build the Ghidra plugin:"
              echo "  1. Set GHIDRA_INSTALL_DIR to your Ghidra installation"
              echo "  2. cd ghidra-plugin && gradle buildExtension"
            '';
          };
        }
      );
}
