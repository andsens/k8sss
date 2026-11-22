{
  description = "k8sss";
  inputs = {
    systems.url = "github:nix-systems/default-linux";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts.url = "github:hercules-ci/flake-parts";
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
        # The digest and Nix hash of each image the module names by default, as `{ "name:tag" = { digest; hash; }; }`,
        # for consumers that preload the images (homelab-shared's lib.images.locked reads it). The pins workflow
        # writes it whenever it moves a default, so a consumer's k8sss always comes with the hashes of its own refs.
        flake.lib.imageLock = ./nix/modules/default/images.lock;
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
            # Every image the module names by default is in imageLock
            checks.image-lock =
              let
                options =
                  (inputs.nixpkgs.lib.nixosSystem {
                    modules = [
                      self.nixosModules.default
                      { nixpkgs.hostPlatform = pkgs.stdenv.hostPlatform.system; }
                    ];
                  }).options.k8sss.images;
                refs = map (image: image.default) (lib.attrValues options);
                lock = lib.importJSON self.lib.imageLock;
                missing = lib.filter (ref: !lock ? ${ref}) refs;
              in
              assert lib.assertMsg (missing == [ ])
                "Not in nix/modules/default/images.lock, run `nix run github:nixos-homelab/shared#lock-images -- --lock nix/modules/default/images.lock ${lib.concatStringsSep " " refs}`: ${lib.concatStringsSep ", " missing}";
              pkgs.runCommand "image-lock" { } "touch $out";
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
                vendorHash = "sha256-9ULo7SpCWM5FJW/KygCA69UNtD3abhPLhitDXM9HeiM=";
                nativeBuildInputs = lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.pkg-config;
                buildInputs = lib.optional pkgs.stdenv.hostPlatform.isLinux (lib.getDev pkgs.pcsclite);
              };
            };
          };
      }
    );
}
