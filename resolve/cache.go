package resolve

import (
	"dns"
	"sync"
)

type cacheKey struct {
	name  string
	typ   dns.QueryType
	class dns.QueryClass
}

func newCacheKey(q dns.Question) cacheKey {
	return cacheKey{
		name:  string(q.Name.String()),
		typ:   q.Type,
		class: q.Class,
	}
}

type Cache struct {
	cache map[cacheKey][]dns.Resource
	mutex *sync.Mutex
}

// TODO: need a strategy for handling TTLs

func (c Cache) Get(q dns.Question) ([]dns.Resource, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	rs, ok := c.cache[newCacheKey(q)]
	return rs, ok
}

func (c Cache) Put(question dns.Question, resources []dns.Resource) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache[newCacheKey(question)] = resources
}

func NewCache() Cache {
	return Cache{
		cache: make(map[cacheKey][]dns.Resource),
		mutex: &sync.Mutex{},
	}
}
