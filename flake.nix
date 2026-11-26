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
          manifestVersion = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          kiri = pkgs.rustPlatform.buildRustPackage {
            pname = "kiri";
            version =
              if manifestVersion != "0.0.0" then manifestVersion
              else "0.0.0-${self.shortRev or self.dirtyShortRev or "dev"}";
            src = self;

            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "-p" "kiri" "-p" "kiri-init" ];
            cargoTestFlags = [ "-p" "kiri" "-p" "kiri-init" ];

            # Some unit tests inspect /home or require real root namespaces absent in the Nix build sandbox.
            doCheck = false;

            postInstall = ''
              install -Dm644 packaging/linux/dev.kiri.host-access.policy \
                "$out/share/polkit-1/actions/dev.kiri.host-access.policy"
            '';

            meta = {
              description = "Small, fast container runtime";
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

            environment.etc."NetworkManager/conf.d/kiri.conf" = lib.mkIf config.networking.networkmanager.enable {
              source = ./packaging/linux/kiri-nm.conf;
            };

            systemd.services.kiri = {
              description = "Kiri container engine";
              documentation = [ "https://runkiri.com" ];
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" "docker.service" ];
              path = [ pkgs.nftables pkgs.iptables pkgs.coreutils ];
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/kiri daemon";
                ExecStartPost = "-${pkgs.runtimeShell} -c '[ \"$(readlink /run/docker.sock)\" = /run/kiri/docker.sock ] || [ -e /run/docker.sock ] || [ -L /run/docker.sock ] || ln -s /run/kiri/docker.sock /run/docker.sock'";
                ExecStopPost = "-${pkgs.runtimeShell} -c '[ \"$(readlink /run/docker.sock)\" != /run/kiri/docker.sock ] || rm -f /run/docker.sock'";
                Environment = [
                  "KIRI_SOCKET=/run/kiri/docker.sock"
                  "KIRI_SOCKET_GROUP=kiri"
                  "HOME=/var/lib/kiri-daemon"
                ];
                Delegate = true;
                LimitNPROC = "infinity";
                LimitCORE = "infinity";
                TasksMax = "infinity";
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
