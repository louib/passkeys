{
  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    fenix,
  }: (
    flake-utils.lib.eachDefaultSystem (
      system: (
        let
          pkgs = nixpkgs.legacyPackages.${system};
          targetMuslSystem = "x86_64-unknown-linux-musl";
          fenixPkgs = fenix.packages.${system};
          muslToolchain = fenixPkgs.combine [
            fenixPkgs.minimal.cargo
            fenixPkgs.minimal.rustc
            fenixPkgs.targets.${targetMuslSystem}.latest.rust-std
          ];
        in {
          devShells = {
            default = pkgs.mkShell {
              buildInputs = with pkgs; [
                cargo
                rustc
                rustfmt
                rust-analyzer
                cargo-tarpaulin
                cargo-msrv
                cargo-hack
              ];
            };

            # This shell cross-compiles with Rust's musl target. Keeping it
            # minimal prevents host libraries from masking native dependencies.
            musl = pkgs.mkShell {
              buildInputs = [
                muslToolchain
                pkgs.binutils
              ];
              shellHook = ''
                export CARGO_BUILD_TARGET="${targetMuslSystem}"
              '';
            };
          };
        }
      )
    )
  );
}
