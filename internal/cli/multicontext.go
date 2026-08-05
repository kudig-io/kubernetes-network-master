package cli

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// clientsetForContext builds a typed clientset for a specific kubeconfig
// context, bypassing the factory's current-context caching. Used by multi-
// cluster commands (knm mc ...).
func clientsetForContext(g *GlobalFlags, context string) (kubernetes.Interface, error) {
	// Reuse the factory's loading rules + explicit context override.
	loader := g.factory.Raw.ToRawKubeConfigLoader()
	rawConfig, err := loader.RawConfig()
	if err != nil {
		return nil, err
	}
	return clientsetFromRawConfig(rawConfig, context)
}

// clientsetFromRawConfig constructs a clientset by overriding the active
// context in an in-memory raw config.
func clientsetFromRawConfig(rawConfig api.Config, context string) (kubernetes.Interface, error) {
	if _, ok := rawConfig.Contexts[context]; !ok {
		// Fall back to current context silently.
		context = rawConfig.CurrentContext
	}
	rawConfig.CurrentContext = context
	cfg, err := clientcmd.NewNonInteractiveClientConfig(
		rawConfig, context, &clientcmd.ConfigOverrides{}, nil,
	).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
