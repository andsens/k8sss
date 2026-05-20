{ self, inputs, ... }:
{
  lib,
  pkgs,
  config,
  ...
}:
with builtins;
let
  cfg = config.k8sss;
  adminSSHKeys = lib.flatten (
    map (u: u.openssh.authorizedKeys.keys) (
      lib.sortOn (u: u.uid) (
        filter (
          u:
          u.enable
          && u.isNormalUser
          && u.uid != null
          && elem "wheel" u.extraGroups
          && length openssh.authorizedKeys.keys > 0
        ) (attrValues config.users.users)
      )
    )
  );
  adminJWKs = lib.splitString "\n" (
    lib.trim (
      builtins.readFile (
        pkgs.stdenvNoCC.mkDerivation {
          name = "create-jwks";
          phases = [ "installPhase" ];
          installPhase = ''
            runHook preInstall
            ${lib.join "\n" (
              map (key: ''
                jwk=$(${lib.getExe pkgs.step-cli} crypto key format --jwk <<<"${key}")
                kid=$(${lib.getExe pkgs.step-cli} crypto jwk thumbprint <<<"$jwk")
                ${lib.getExe pkgs.jq} -c --arg kid "$kid" '.kid=$kid' <<<"$jwk" >>$out
              '') adminSSHKeys
            )}
            runHook postInstall
          '';
        }
      )
    )
  );
in
{
  options.k8sss = {
    enable = lib.mkEnableOption "k8sss";
    dnsNames = lib.mkOption {
      description = "List of DNS names step-ca should generate a TLS host certificate for";
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
    # Generate JWKs with `step crypto jwk create --force --use sig --from-pem=<(step kms key $keyuri) /dev/stdout /dev/null | jq -c`
    adminKeys = lib.mkOption {
      description = "List of JWKs that may request a kubeapi client certificate";
      type = lib.types.listOf lib.types.str;
      default = adminJWKs;
      defaultText = "All authorized SSH keys of all users in 'wheel' converted to JWKs";
    };
    clientCaCertPath = lib.mkOption {
      description = "Path to the kube client certificate";
      type = lib.types.str;
      default = "/var/lib/rancher/k3s/server/tls/client-ca.crt";
    };
    clientCaKeyPath = lib.mkOption {
      description = "Path to the kube client certificate key";
      type = lib.types.str;
      default = "/var/lib/rancher/k3s/server/tls/client-ca.key";
    };
    nodePort = lib.mkOption {
      description = "Whether to create a nodeport service and which port to listen on (null to disable)";
      type = lib.types.nullOr lib.types.int;
      default = 9000;
    };
  };
  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.optional (cfg.nodePort != null) cfg.nodePort;
    kubetree.resources.k8sss =
      (lib.optionalAttrs (cfg.nodePort != null) {
        nodePortService = {
          apiVersion = "v1";
          kind = "Service";
          metadata = {
            namespace = "k8sss";
            name = "k8sss-nodeport";
            labels."app.kubernetes.io/name" = "k8sss";
          };
          spec = {
            type = "NodePort";
            selector."app.kubernetes.io/name" = "k8sss";
            portsByName.api = {
              nodePort = cfg.nodePort;
              targetPort = "api";
            };
          };
        };
      })
      // {
        namespace = {
          apiVersion = "v1";
          kind = "Namespace";
          metadata.name = "k8sss";
        };
        config = {
          apiVersion = "v1";
          kind = "ConfigMap";
          metadata = {
            namespace = "k8sss";
            name = "config";
            labels."app.kubernetes.io/name" = "k8sss";
          };
          data = {
            "admin-keys.json" = builtins.toJSON (map builtins.fromJSON cfg.adminKeys);
            "ca.json" = builtins.readFile ../../../deploy/base/ca.json;
            "admin.tpl" = builtins.readFile ../../../deploy/base/admin.tpl;
            "setup-script.sh" = builtins.readFile ../../../deploy/base/setup.sh;
          };
        };
        service = {
          apiVersion = "v1";
          kind = "Service";
          metadata = {
            namespace = "k8sss";
            name = "k8sss";
            labels."app.kubernetes.io/name" = "k8sss";
          };
          spec = {
            type = "ClusterIP";
            selector."app.kubernetes.io/name" = "k8sss";
            portsByName.api = {
              port = 9000;
              targetPort = "api";
            };
          };
        };
        deployment = {
          apiVersion = "apps/v1";
          kind = "Deployment";
          metadata = {
            namespace = "k8sss";
            name = "k8sss";
            labels."app.kubernetes.io/name" = "k8sss";
          };
          spec = {
            selector.matchLabels."app.kubernetes.io/name" = "k8sss";
            template = {
              metadata.labels."app.kubernetes.io/name" = "k8sss";
              spec = {
                nodeSelector."node-role.kubernetes.io/control-plane" = "true";
                serviceAccountName = "k8sss";
                securityContext.fsGroup = 1000;
                initContainersByName.setup-k8sss-config = {
                  image = "ghcr.io/andsens/k8sss-bootstrap";
                  command = [ "bash" ];
                  args = [
                    "-c"
                    "/home/step/setup.sh"
                  ];
                  securityContext = {
                    allowPrivilegeEscalation = false;
                    readOnlyRootFilesystem = true;
                    capabilities.drop = [ "ALL" ];
                  };
                  envByName.DNSNAMES.value = lib.join "," cfg.dnsNames;
                  volumeMountsByPath = {
                    "/home/step/setup.sh" = {
                      name = "config";
                      subPath = "setup.sh";
                    };
                    "/home/step/ca.json" = {
                      name = "config";
                      subPath = "ca.json";
                    };
                    "/home/step/admin-keys.json" = {
                      name = "config";
                      subPath = "admin-keys.json";
                    };
                    "/home/step/kube-api-secrets/kube_apiserver_client_ca.crt" = {
                      name = "k8sss-cert";
                      readOnly = true;
                    };
                    "/home/step/kube-api-secrets/kube_apiserver_client_ca_key" = {
                      name = "k8sss-key";
                      readOnly = true;
                    };
                    "/home/step/secrets".name = "secrets";
                    "/home/step/config".name = "config-rw";
                  };
                };
                containersByName.step-ca = {
                  image = "cr.step.sm/smallstep/step-ca";
                  command = [ "/usr/local/bin/step-ca" ];
                  args = [ "/home/step/config/ca.json" ];
                  securityContext = {
                    allowPrivilegeEscalation = false;
                    readOnlyRootFilesystem = true;
                    capabilities.add = [ "NET_BIND_SERVICE" ];
                    capabilities.drop = [ "ALL" ];
                  };
                  portsByName.api.containerPort = 9000;
                  livenessProbe = {
                    httpGet = {
                      path = "/health";
                      port = "api";
                      scheme = "HTTPS";
                    };
                    initialDelaySeconds = 5;
                  };
                  readinessProbe = {
                    httpGet = {
                      path = "/health";
                      port = "api";
                      scheme = "HTTPS";
                    };
                    initialDelaySeconds = 5;
                  };
                  volumeMountsByPath = {
                    "/home/step/secrets" = {
                      name = "secrets";
                      readOnly = true;
                    };
                    "/home/step/admin.tpl" = {
                      name = "config";
                      subPath = "admin.tpl";
                    };
                    "/home/step/config/ca.json" = {
                      name = "config-rw";
                      subPath = "ca.json";
                    };
                    "/home/step/db".name = "database";
                  };
                };
                volumesByName = {
                  config.configMap.name = "config";
                  secrets.emptyDir.medium = "Memory";
                  k8sss-cert.hostPath = {
                    path = cfg.clientCaCertPath;
                    type = "File";
                  };
                  k8sss-key.hostPath = {
                    path = cfg.clientCaKeyPath;
                    type = "File";
                  };
                  config-rw.emptyDir = { };
                  database.emptyDir = { };
                };
              };
            };
          };
        };
      };
  };
}
