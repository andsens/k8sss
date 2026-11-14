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
  # A key with authorized_keys options (restrict, command=, from=, ...) is
  # limited in a way its JWK cannot carry over, so it is left out.
  isPlainKey = key: match "(ssh|ecdsa-sha2|sk)-[^ ]+ .*" (lib.trim key) != null;
  adminSSHKeys = filter isPlainKey (
    lib.flatten (
      map (u: u.openssh.authorizedKeys.keys) (
        lib.sortOn (u: u.uid) (
          filter (
            u:
            u.enable
            && u.isNormalUser
            && u.uid != null
            && elem "wheel" u.extraGroups
            && length u.openssh.authorizedKeys.keys > 0
          ) (attrValues config.users.users)
        )
      )
    )
  );
  adminJWKs = lib.optionals (adminSSHKeys != [ ]) (
    lib.splitString "\n" (
      lib.trim (
        builtins.readFile (
          pkgs.stdenvNoCC.mkDerivation {
            name = "create-jwks";
            phases = [ "installPhase" ];
            installPhase = ''
              runHook preInstall
              ${lib.join "\n" (
                map (key: ''
                  jwk=$(${lib.getExe pkgs.step-cli} crypto key format --jwk <<<${lib.escapeShellArg key})
                  kid=$(${lib.getExe pkgs.step-cli} crypto jwk thumbprint <<<"$jwk")
                  ${lib.getExe pkgs.jq} -c --arg kid "$kid" '.kid=$kid' <<<"$jwk" >>$out
                '') adminSSHKeys
              )}
              runHook postInstall
            '';
          }
        )
      )
    )
  );
in
{
  options.k8sss = {
    enable = lib.mkEnableOption "k8sss";
    dnsNames = lib.mkOption {
      description = "List of DNS names step-ca should generate a TLS host certificate for";
      type = lib.types.nonEmptyListOf lib.types.str;
    };
    # Generate JWKs with `step crypto jwk create --force --use sig --from-pem=<(step kms key $keyuri) /dev/stdout /dev/null | jq -c`
    adminKeys = lib.mkOption {
      description = "List of JWKs that may request a kubeapi client certificate";
      type = lib.types.listOf lib.types.str;
      default = adminJWKs;
      defaultText = "All authorized SSH keys without options of all users in 'wheel' converted to JWKs";
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
    images = {
      bootstrap = lib.mkOption {
        description = "Image of the init container that writes step-ca's configuration";
        type = lib.types.str;
        # Rewritten by .github/workflows/pins.yaml to the sha-tagged image built from the bumping commit
        default = "ghcr.io/andsens/k8sss-bootstrap:sha-5e1e919";
      };
      step-ca = lib.mkOption {
        description = "Image of step-ca";
        type = lib.types.str;
        # Kept in step with deploy/base/deployment.yaml by .github/workflows/pins.yaml, which is where Dependabot can
        # see it
        default = "smallstep/step-ca:0.30.2";
      };
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.adminKeys != [ ];
        message = "k8sss needs at least one admin key in k8sss.adminKeys. By default those are the plain SSH keys (without options) in openssh.authorizedKeys.keys of normal users in the wheel group with a uid set, and there are none.";
      }
    ];
    networking.firewall.allowedTCPPorts = lib.optional (cfg.nodePort != null) cfg.nodePort;
    # The objects k3s applies from its manifest k8sss. Lists stay sorted by name, as they were before they were written
    # out here, so the pod template is unchanged and nothing restarts
    services.k3s.manifests.k8sss.content =
      let
        metadata = {
          namespace = "k8sss";
          labels."app.kubernetes.io/name" = "k8sss";
        };
        selector."app.kubernetes.io/name" = "k8sss";
      in
      [
        {
          apiVersion = "v1";
          kind = "Namespace";
          metadata.name = "k8sss";
        }
        {
          apiVersion = "v1";
          kind = "ConfigMap";
          metadata = metadata // {
            name = "k8sss";
          };
          data = {
            "admin-keys.json" = builtins.toJSON (map builtins.fromJSON cfg.adminKeys);
            "ca.json" = builtins.readFile ../../../deploy/base/ca.json;
            "client.tpl" = builtins.readFile ../../../deploy/base/client.tpl;
            "setup.sh" = builtins.readFile ../../../deploy/base/setup.sh;
          };
        }
        {
          apiVersion = "v1";
          kind = "ServiceAccount";
          metadata = metadata // {
            name = "k8sss";
          };
          automountServiceAccountToken = false;
        }
        {
          apiVersion = "v1";
          kind = "Service";
          metadata = metadata // {
            name = "k8sss";
          };
          spec = {
            type = "ClusterIP";
            inherit selector;
            ports = [
              {
                name = "api";
                port = 9000;
                targetPort = "api";
              }
            ];
          };
        }
      ]
      ++ lib.optional (cfg.nodePort != null) {
        apiVersion = "v1";
        kind = "Service";
        metadata = metadata // {
          name = "k8sss-nodeport";
        };
        spec = {
          type = "NodePort";
          inherit selector;
          ports = [
            {
              name = "api";
              port = 9000;
              nodePort = cfg.nodePort;
              targetPort = "api";
            }
          ];
        };
      }
      ++ [
        {
          apiVersion = "apps/v1";
          kind = "Deployment";
          metadata = metadata // {
            name = "k8sss";
          };
          spec = {
            selector.matchLabels = selector;
            template = {
              metadata.labels = selector;
              spec = {
                nodeSelector."node-role.kubernetes.io/control-plane" = "true";
                serviceAccountName = "k8sss";
                automountServiceAccountToken = false;
                securityContext.fsGroup = 1000;
                initContainers = [
                  {
                    name = "setup-k8sss-config";
                    image = cfg.images.bootstrap;
                    command = [ "bash" ];
                    args = [ "/home/step/setup.sh" ];
                    securityContext = {
                      allowPrivilegeEscalation = false;
                      readOnlyRootFilesystem = true;
                      capabilities.add = [ "CHOWN" ];
                      capabilities.drop = [ "ALL" ];
                    };
                    env = [
                      {
                        name = "DNSNAMES";
                        value = lib.join "," cfg.dnsNames;
                      }
                    ];
                    volumeMounts = [
                      {
                        mountPath = "/home/step/admin-keys.json";
                        name = "config";
                        subPath = "admin-keys.json";
                      }
                      {
                        mountPath = "/home/step/ca.json";
                        name = "config";
                        subPath = "ca.json";
                      }
                      {
                        mountPath = "/home/step/config";
                        name = "config-rw";
                      }
                      {
                        mountPath = "/home/step/kube-api-secrets/kube_apiserver_client_ca.crt";
                        name = "k8sss-cert";
                        readOnly = true;
                      }
                      {
                        mountPath = "/home/step/kube-api-secrets/kube_apiserver_client_ca_key";
                        name = "k8sss-key";
                        readOnly = true;
                      }
                      {
                        mountPath = "/home/step/secrets";
                        name = "secrets";
                      }
                      {
                        mountPath = "/home/step/setup.sh";
                        name = "config";
                        subPath = "setup.sh";
                      }
                    ];
                  }
                ];
                containers = [
                  {
                    name = "step-ca";
                    image = cfg.images.step-ca;
                    command = [ "/usr/local/bin/step-ca" ];
                    args = [ "/home/step/config/ca.json" ];
                    securityContext = {
                      allowPrivilegeEscalation = false;
                      readOnlyRootFilesystem = true;
                      capabilities.add = [ "NET_BIND_SERVICE" ];
                      capabilities.drop = [ "ALL" ];
                    };
                    ports = [
                      {
                        name = "api";
                        containerPort = 9000;
                      }
                    ];
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
                    volumeMounts = [
                      {
                        mountPath = "/home/step/client.tpl";
                        name = "config";
                        subPath = "client.tpl";
                      }
                      {
                        mountPath = "/home/step/config/ca.json";
                        name = "config-rw";
                        subPath = "ca.json";
                      }
                      {
                        mountPath = "/home/step/db";
                        name = "database";
                      }
                      {
                        mountPath = "/home/step/secrets";
                        name = "secrets";
                        readOnly = true;
                      }
                    ];
                  }
                ];
                volumes = [
                  {
                    name = "config";
                    configMap.name = "k8sss";
                  }
                  {
                    name = "config-rw";
                    emptyDir = { };
                  }
                  {
                    name = "database";
                    emptyDir = { };
                  }
                  {
                    name = "k8sss-cert";
                    hostPath = {
                      path = cfg.clientCaCertPath;
                      type = "File";
                    };
                  }
                  {
                    name = "k8sss-key";
                    hostPath = {
                      path = cfg.clientCaKeyPath;
                      type = "File";
                    };
                  }
                  {
                    name = "secrets";
                    emptyDir.medium = "Memory";
                  }
                ];
              };
            };
          };
        }
      ];
  };
}
