// Copyright Aeraki Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/aeraki-framework/aeraki/client-go/pkg/apis/metaprotocol/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ApplicationProtocolLister helps list ApplicationProtocols.
// All objects returned here must be treated as read-only.
type ApplicationProtocolLister interface {
	// List lists all ApplicationProtocols in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.ApplicationProtocol, err error)
	// ApplicationProtocols returns an object that can list and get ApplicationProtocols.
	ApplicationProtocols(namespace string) ApplicationProtocolNamespaceLister
	ApplicationProtocolListerExpansion
}

// applicationProtocolLister implements the ApplicationProtocolLister interface.
type applicationProtocolLister struct {
	indexer cache.Indexer
}

// NewApplicationProtocolLister returns a new ApplicationProtocolLister.
func NewApplicationProtocolLister(indexer cache.Indexer) ApplicationProtocolLister {
	return &applicationProtocolLister{indexer: indexer}
}

// List lists all ApplicationProtocols in the indexer.
func (s *applicationProtocolLister) List(selector labels.Selector) (ret []*v1alpha1.ApplicationProtocol, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ApplicationProtocol))
	})
	return ret, err
}

// ApplicationProtocols returns an object that can list and get ApplicationProtocols.
func (s *applicationProtocolLister) ApplicationProtocols(namespace string) ApplicationProtocolNamespaceLister {
	return applicationProtocolNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ApplicationProtocolNamespaceLister helps list and get ApplicationProtocols.
// All objects returned here must be treated as read-only.
type ApplicationProtocolNamespaceLister interface {
	// List lists all ApplicationProtocols in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.ApplicationProtocol, err error)
	// Get retrieves the ApplicationProtocol from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.ApplicationProtocol, error)
	ApplicationProtocolNamespaceListerExpansion
}

// applicationProtocolNamespaceLister implements the ApplicationProtocolNamespaceLister
// interface.
type applicationProtocolNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ApplicationProtocols in the indexer for a given namespace.
func (s applicationProtocolNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.ApplicationProtocol, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ApplicationProtocol))
	})
	return ret, err
}

// Get retrieves the ApplicationProtocol from the indexer for a given namespace and name.
func (s applicationProtocolNamespaceLister) Get(name string) (*v1alpha1.ApplicationProtocol, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("applicationprotocol"), name)
	}
	return obj.(*v1alpha1.ApplicationProtocol), nil
}
