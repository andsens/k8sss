# k8sss

Get access to your Kubernetes cluster using your SSH key (or YubiKey, TPM chip,
Google login, anything [supported by Smallstep](https://smallstep.com/docs/step-ca/provisioners/) really).

Note that the key itself is not used for accessing the cluster, instead k8sss
generates key on disk and obtains a short-lived certificate (30 min.) that is
reissued every 15 min.  
To authenticate with your cluster directly via an HSM, see [step-kmsproxy-plugin](https://github.com/orbit-online/step-kmsproxy-plugin).

## Installation

The `k8sss` tool can be installed through [μpkg](https://github.com/orbit-online/upkg).
Check [the latest release](https://github.com/andsens/k8sss/releases/latest) for
a copy & paste string with the proper shasum.

```
# DON'T COPY THIS, SEE THE LATEST RELEASE
$ upkg add -g 'https://github.com/andsens/k8sss/releases/download/v0.0.0/k8sss.tar.gz' f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2
upkg: Added 'https://github.com/andsens/k8sss/releases/download/v0.0.0/k8sss.tar.gz'
```

The manifest can be deployed with `kubectl apply -k deploy/`.

## Usage

Run `k8sss setup <kube-api>:6443`

```
$ k8sss setup nas:6443
k8sss: No trust has been established with this Kubernetes cluster yet.
The root certificate fingerprint is f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2
Do you want to establish that trust now? [y/N]y
k8sss: Downloading Kubernetes API Client CA certificate
k8sss: Setting up ~/.kube/config.yaml
Cluster "nas" set.
User "system:admin@nas" set.
Context "nas" modified.

$ kubectl --context nas -n kube-system get pod
NAME                       READY   STATUS    RESTARTS   AGE
coredns-77dbf85789-g7qkm   2/2     Running   0          2d15h
```

Run `k8sss --help` for details on how to adjust things like the smallstep ca endpoint (assumed to be `<kube-api>:9000`).

## Customizing access

The [setup script](deploy/setup-kube-client-ca-config.sh) reads each line from
`/home/admin/.ssh/authorized_keys` (mounted via `hostPath`) and converts
it to a JWK that is added to the step-ca provisioner config.

The script and the deployment need to be modified if you wish to change
how step-ca authenticates users.
