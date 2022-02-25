package utils

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type RemoteSecretCluster struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}

type RemoteSecretClusterListItem struct {
	Cluster RemoteSecretCluster `yaml:"cluster"`
	Name    string              `yaml:"name"`
}

type RemoteSecretUser struct {
	Name string                `yaml:"name"`
	User RemoteSecretUserToken `yaml:"user"`
}

type RemoteSecretUserToken struct {
	Token string `yaml:"token"`
}
type RemoteSecret struct {
	APIVersion string                        `yaml:"apiVersion"`
	Clusters   []RemoteSecretClusterListItem `yaml:"clusters"`
	Contexts   []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []RemoteSecretUser `yaml:"users"`
}

// Point the k8s client to a remote cluster's API server
func UseRemoteCreds(remoteSecret *RemoteSecret) (*rest.Config, error) {
	caData := remoteSecret.Clusters[0].Cluster.CertificateAuthorityData
	rootCaDecoded, err := base64.StdEncoding.DecodeString(caData)
	if err != nil {
		return nil, err
	}
	// Basically implement rest.InClusterConfig() with the remote creds
	tlsClientConfig := rest.TLSClientConfig{
		CAData: []byte(rootCaDecoded),
	}

	serverParse := strings.Split(remoteSecret.Clusters[0].Cluster.Server, ":")
	if len(serverParse) != 3 && len(serverParse) != 2 {
		return nil, errors.New("Invalid remote API server URL")
	}
	host := strings.TrimPrefix(serverParse[1], "//")

	port := "443"
	if len(serverParse) == 3 {
		port = serverParse[2]
	}

	if !strings.EqualFold(serverParse[0], "https") {
		return nil, errors.New("Only HTTPS protocol is allowed in remote API server URL")
	}

	// There's no need to add the BearerToken because it's ignored later on
	return &rest.Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		TLSClientConfig: tlsClientConfig,
	}, nil
}

func ParseRemoteSecretBytes(secretBytes []byte) (*RemoteSecret, error) {
	secret := &RemoteSecret{}
	err := yaml.Unmarshal(secretBytes, &secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func getRemoteK8s(clientSet *kubernetes.Clientset) ([]*kubernetes.Clientset, error) {
	var clientSets []*kubernetes.Clientset

	secrets, err := clientSet.CoreV1().Secrets("").List(context.Background(), metav1.ListOptions{LabelSelector: "istio/remoteKiali=true"})
	if err != nil {
		return nil, errors.New("failed to get remote k8s Secrets")

	}

	log.Errorf("Error getRemoteK8s: %v", secrets)
	for _, secret := range secrets.Items {
		clusterName, ok := secret.Annotations["networking.istio.io/cluster"]
		if !ok {
			continue
		}

		kubeconfigFile, ok := secret.Data[clusterName]
		if !ok {
			log.Errorf("Error get secret: %v, %v", secret.Data, clusterName)
			continue
		}
		remoteSecret, parseErr := ParseRemoteSecretBytes(kubeconfigFile)
		if parseErr != nil {
			log.Errorf("Error ParseRemoteSecretBytes: %v", parseErr)
			continue
		}

		restConfig, restConfigErr := UseRemoteCreds(remoteSecret)
		if restConfigErr != nil {
			log.Errorf("Error using remote creds: %v", restConfigErr)
			continue
		}

		restConfig.Timeout = 15 * time.Second
		restConfig.BearerToken = remoteSecret.Users[0].User.Token

		clientSet, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			log.Errorf("Error using remote creds: %v", err)
			continue

		}
		clientSets = append(clientSets, clientSet)

	}

	return clientSets, nil
}

func NewRemoteKubeClient(client *kubernetes.Clientset) ([]*kubernetes.Clientset, error) {
	return getRemoteK8s(client)
}
