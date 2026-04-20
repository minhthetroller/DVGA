package coretest

import (
	"net/http"
	"sync"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDifficulty(t *testing.T) {
	tests := []struct {
		input string
		want  core.Difficulty
	}{
		{"easy", core.Easy},
		{"Easy", core.Easy},
		{"EASY", core.Easy},
		{"medium", core.Medium},
		{"Medium", core.Medium},
		{"hard", core.Hard},
		{"Hard", core.Hard},
		{"HARD", core.Hard},
		{"unknown", core.Easy}, // unrecognised input defaults to Easy
		{"", core.Easy},
		{"0", core.Easy},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := core.ParseDifficulty(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDifficultyString(t *testing.T) {
	assert.Equal(t, "Easy", core.Easy.String())
	assert.Equal(t, "Medium", core.Medium.String())
	assert.Equal(t, "Hard", core.Hard.String())
}

func TestSafeDifficultyGetSet(t *testing.T) {
	sd := core.NewSafeDifficulty(core.Easy)
	assert.Equal(t, core.Easy, sd.Get())

	sd.Set(core.Medium)
	assert.Equal(t, core.Medium, sd.Get())

	sd.Set(core.Hard)
	assert.Equal(t, core.Hard, sd.Get())
}

func TestSafeDifficultyConcurrent(t *testing.T) {
	sd := core.NewSafeDifficulty(core.Easy)
	var wg sync.WaitGroup

	// 50 writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sd.Set(core.Difficulty(i % 3))
		}(i)
	}
	// 50 readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := sd.Get()
			// just assert it is a valid value
			assert.True(t, d == core.Easy || d == core.Medium || d == core.Hard)
		}()
	}
	wg.Wait()
}

func TestRegistryRegisterAndBuild(t *testing.T) {
	reg := core.NewRegistry()
	callCount := 0
	reg.Register("test-mod", func(d core.Difficulty) core.VulnModule {
		callCount++
		return &stubModule{id: "test-mod", difficulty: d}
	})

	mod, err := reg.Build("test-mod", core.Medium)
	require.NoError(t, err)
	assert.Equal(t, "test-mod", mod.Meta().ID)
	assert.Equal(t, core.Medium, mod.Meta().Difficulty)
	assert.Equal(t, 1, callCount)
}

func TestRegistryBuildUnknown(t *testing.T) {
	reg := core.NewRegistry()
	_, err := reg.Build("nonexistent", core.Easy)
	assert.Error(t, err)
}

func TestRegistryAll(t *testing.T) {
	reg := core.NewRegistry()
	reg.Register("alpha", func(d core.Difficulty) core.VulnModule { return &stubModule{id: "alpha"} })
	reg.Register("beta", func(d core.Difficulty) core.VulnModule { return &stubModule{id: "beta"} })

	all := reg.All(core.Easy)
	assert.Len(t, all, 2)
}

func TestRegistryIDs(t *testing.T) {
	reg := core.NewRegistry()
	reg.Register("z-mod", func(d core.Difficulty) core.VulnModule { return &stubModule{id: "z-mod"} })
	reg.Register("a-mod", func(d core.Difficulty) core.VulnModule { return &stubModule{id: "a-mod"} })

	ids := reg.IDs()
	require.Len(t, ids, 2)
	assert.Equal(t, "a-mod", ids[0])
	assert.Equal(t, "z-mod", ids[1])
}

func TestRegistryCategories(t *testing.T) {
	reg := core.NewRegistry()
	reg.Register("inj-1", func(d core.Difficulty) core.VulnModule {
		return &stubModule{id: "inj-1", category: "Injection"}
	})
	reg.Register("inj-2", func(d core.Difficulty) core.VulnModule {
		return &stubModule{id: "inj-2", category: "Injection"}
	})
	reg.Register("auth-1", func(d core.Difficulty) core.VulnModule {
		return &stubModule{id: "auth-1", category: "Auth"}
	})

	cats := reg.Categories(core.Easy)
	assert.Len(t, cats["Injection"], 2)
	assert.Len(t, cats["Auth"], 1)
}

func TestChainApplyPassthrough(t *testing.T) {
	chain := core.NewChain()
	inner := &stubModule{id: "inner"}
	wrapped := chain.Apply(inner)

	// No decorators → wrapped IS the inner module
	assert.Equal(t, "inner", wrapped.Meta().ID)
}

func TestChainApplyWithDecorator(t *testing.T) {
	chain := core.NewChain()
	chain.Use(&countingDecorator{})

	inner := &stubModule{id: "inner"}
	wrapped := chain.Apply(inner)

	// Should be wrapped; meta delegates to inner
	assert.Equal(t, "inner", wrapped.Meta().ID)
}

// --- stub types for core tests ---

type stubModule struct {
	id         string
	category   string
	difficulty core.Difficulty
}

func (s *stubModule) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {}
func (s *stubModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{ID: s.id, Category: s.category, Difficulty: s.difficulty}
}

type countingDecorator struct{ wrapped int }

func (d *countingDecorator) Wrap(inner core.VulnModule) core.VulnModule {
	d.wrapped++
	return inner
}
