{
  description = "Kiri container engine";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          kiri = pkgs.rustPlatform.buildRustPackage {
            pname = "kiri";
            version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
            src = self;

            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "-p" "kiri" "-p" "kiri-init" ];
            cargoTestFlags = [ "-p" "kiri" "-p" "kiri-init" ];

            # dont run cargo test
            doCheck = false;

            meta = {
              description = "Tiny, fast container runtime";
              homepage = "https://runkiri.com/";
              license = pkgs.lib.licenses.asl20;
              platforms = systems;
              mainProgram = "kiri";
            };
          };
        in
        {
          inherit kiri;
          default = kiri;
        });
    in
    {
      packages = packages;

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.kiri;
        in
        {
          options.services.kiri = {
            enable = lib.mkEnableOption "the Kiri container engine";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.kiri;
              defaultText = lib.literalExpression "inputs.kiri.packages.\${pkgs.stdenv.hostPlatform.system}.kiri";
              description = "The Kiri package to run and install.";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            users.groups.kiri = { };

            systemd.services.kiri = {
              description = "Kiri container engine";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/kiri daemon";
                Environment = [
                  "KIRI_SOCKET=/run/kiri/docker.sock"
                  "KIRI_SOCKET_GROUP=kiri"
                  "HOME=/var/lib/kiri-daemon"
                ];
                Delegate = true;
                KillMode = "mixed";
                Restart = "on-failure";
                RuntimeDirectory = "kiri";
                RuntimeDirectoryMode = "0755";
                StateDirectory = "kiri-daemon";
                StateDirectoryMode = "0700";
                UMask = "0027";
              };
            };
          };
        };
    };
}
