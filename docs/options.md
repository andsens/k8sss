## k8sss\.enable



Whether to enable k8sss\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `

*Declared by:*
 - [nix/modules/default/default\.nix](https://github.com/andsens/k8sss/blob/main/nix/modules/default/default.nix)



## k8sss\.adminKeys

List of JWKs that may request a kubeapi client certificate



*Type:*
list of string



*Default:*
` "All authorized SSH keys of all users in 'wheel' converted to JWKs" `

*Declared by:*
 - [nix/modules/default/default\.nix](https://github.com/andsens/k8sss/blob/main/nix/modules/default/default.nix)



## k8sss\.clientCaCertPath



Path to the kube client certificate



*Type:*
string



*Default:*
` "/var/lib/rancher/k3s/server/tls/client-ca.crt" `

*Declared by:*
 - [nix/modules/default/default\.nix](https://github.com/andsens/k8sss/blob/main/nix/modules/default/default.nix)



## k8sss\.clientCaKeyPath



Path to the kube client certificate key



*Type:*
string



*Default:*
` "/var/lib/rancher/k3s/server/tls/client-ca.key" `

*Declared by:*
 - [nix/modules/default/default\.nix](https://github.com/andsens/k8sss/blob/main/nix/modules/default/default.nix)



## k8sss\.dnsNames



List of DNS names step-ca should generate a TLS host certificate for



*Type:*
list of string



*Default:*
` [ ] `

*Declared by:*
 - [nix/modules/default/default\.nix](https://github.com/andsens/k8sss/blob/main/nix/modules/default/default.nix)



## k8sss\.nodePort



Whether to create a nodeport service and which port to listen on (null to disable)



*Type:*
null or signed integer



*Default:*
` 9000 `

*Declared by:*
 - [nix/modules/default/default\.nix](https://github.com/andsens/k8sss/blob/main/nix/modules/default/default.nix)


