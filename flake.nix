{
  description = "k8sss";
  inputs = {
    systems.url = "github:nix-systems/default-linux";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts.url = "github:hercules-ci/flake-parts";
    kubetree = {
      url = "github:andsens/nix-kubetree";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
    };
    kube-generators.url = "github:farcaller/nix-kube-generators";
    docs = {
      url = "github:andsens/nix-docs";
      inputs.systems.follows = "systems";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
    };
  };
  outputs =
    {
      systems,
      flake-parts,
      nixpkgs,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } (
      {
        flake-parts-lib,
        self,
        inputs,
        lib,
        ...
      }:
      let
        inherit (flake-parts-lib) importApply;
      in
      {
        systems = import systems;
        flake.nixosModules.default = importApply ./nix/modules/default { inherit self inputs; };
        perSystem =
          {
            pkgs,
            lib,
            config,
            ...
          }:
          let
            options-docs = inputs.docs.lib.docs.options {
              inherit pkgs;
              modules = lib.attrValues self.nixosModules;
              repoPath = toString self;
              repoLinkPrefix = "https://github.com/andsens/k8sss/blob/main";
            };
          in
          {
            apps.update-docs.program = inputs.docs.lib.utils.updateRepo {
              inherit pkgs;
              paths."docs/options.md" = options-docs;
            };
            packages = {
              inherit options-docs;
              default = config.packages.k8sss;
              # YubiKey and PKCS#11 keys need cgo, which on Linux means
              # pcsclite. macOS reaches the same readers through a system
              # framework and needs nothing extra.
              k8sss = pkgs.buildGo126Module {
                name = "k8sss";
                meta.mainProgram = "k8sss";
                src = ./.;
                vendorHash = "sha256-yw6Nl+D5HTEOurVy7qzugw0IDoDCM+UjY+dK+lbE6Vw=";
                nativeBuildInputs = lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.pkg-config;
                buildInputs = lib.optional pkgs.stdenv.hostPlatform.isLinux (lib.getDev pkgs.pcsclite);
              };
            };
          };
      }
    );
}
