// Package kube centralizes Kubernetes client construction for the CLI.
//
// It wraps kubectl's genericclioptions.ConfigFlags so every knm subcommand
// accepts the familiar --kubeconfig / --context / -n / --as flags and resolves
// a restmapper + typed clientset the same way kubectl does.
package kube

import (
	"fmt"

	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // register all auth providers
	"k8s.io/client-go/rest"
)

// Factory bundles kubectl-style flags with lazily-created clients.
type Factory struct {
	Raw       *genericclioptions.ConfigFlags
	clientset *kubernetes.Clientset
	dyn       dynamic.Interface
	cfg       *rest.Config
	err       error
}

// NewFactory builds a Factory around the given pflag.FlagSet, registering the
// standard kubeconfig flags. Pass nil to use a fresh FlagSet.
func NewFactory(fs *pflag.FlagSet) *Factory {
	rf := genericclioptions.NewConfigFlags(true)
	if fs == nil {
		fs = pflag.NewFlagSet("kube", pflag.ContinueOnError)
	}
	rf.AddFlags(fs)
	return &Factory{Raw: rf}
}

// AddFlags registers the kubeconfig flags on an external FlagSet (cobra's).
func (f *Factory) AddFlags(fs *pflag.FlagSet) {
	f.Raw.AddFlags(fs)
}

// Namespace returns the effective namespace honoring -A/--all-namespaces.
func (f *Factory) Namespace(allNamespaces bool) (string, error) {
	ns, _, err := f.Raw.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return "", err
	}
	if allNamespaces {
		return "", nil
	}
	if ns == "" {
		return "default", nil
	}
	return ns, nil
}

// Config returns the rest.Config (cached). Resolution errors are captured and
// surfaced via Clientset(); callers should check the returned error.
func (f *Factory) Config() (*rest.Config, error) {
	if f.cfg != nil || f.err != nil {
		return f.cfg, f.err
	}
	cfg, err := f.Raw.ToRESTConfig()
	if err != nil {
		f.err = err
		return nil, err
	}
	f.cfg = cfg
	return cfg, nil
}

// Clientset returns a cached typed Kubernetes clientset.
func (f *Factory) Clientset() (kubernetes.Interface, error) {
	if f.clientset != nil {
		return f.clientset, nil
	}
	cfg, err := f.Config()
	if err != nil {
		return nil, fmt.Errorf("resolve kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		f.err = err
		return nil, fmt.Errorf("build clientset: %w", err)
	}
	f.clientset = cs
	return cs, nil
}

// Dynamic returns a cached dynamic client (for CRDs like Gateway API when not
// using the typed gateway-api clientset).
func (f *Factory) Dynamic() (dynamic.Interface, error) {
	if f.dyn != nil {
		return f.dyn, nil
	}
	cfg, err := f.Config()
	if err != nil {
		return nil, fmt.Errorf("resolve kubeconfig: %w", err)
	}
	d, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	f.dyn = d
	return d, nil
}

// CurrentContext returns the active context name (best-effort).
func (f *Factory) CurrentContext() string {
	if f.Raw.Context != nil && *f.Raw.Context != "" {
		return *f.Raw.Context
	}
	raw, err := f.Raw.ToRawKubeConfigLoader().RawConfig()
	if err == nil {
		return raw.CurrentContext
	}
	return ""
}
