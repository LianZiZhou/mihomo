package geodata

import (
	"errors"
	"sync"
	"testing"
)

func TestGeoSiteCacheGenerationCoversReplacementAndFailure(t *testing.T) {
	before := GeoSiteCacheGeneration()
	if before%2 != 0 {
		t.Fatal("initial cache generation is not stable")
	}
	want := errors.New("database replacement failed")
	err := UpdateGeoSiteCache(func() error {
		if during := GeoSiteCacheGeneration(); during != before+1 || during%2 != 1 {
			t.Fatalf("replacement was not covered by an unstable generation: %d", during)
		}
		return want
	})
	if !errors.Is(err, want) || GeoSiteCacheGeneration() != before+2 {
		t.Fatal("failed replacement did not invalidate and finish its generation")
	}
	ClearGeoSiteCache()
	if GeoSiteCacheGeneration() != before+4 {
		t.Fatal("explicit cache clear did not publish a new stable generation")
	}
}

func TestGeoSiteCacheConcurrentClearSerializesGeneration(t *testing.T) {
	before := GeoSiteCacheGeneration()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := UpdateGeoSiteCache(func() error {
					if GeoSiteCacheGeneration()%2 != 1 {
						t.Error("concurrent writers exposed a stable generation inside replacement")
					}
					return nil
				}); err != nil {
					t.Error(err)
				}
				ClearGeoSiteCache()
			}
		}()
	}
	wg.Wait()
	if GeoSiteCacheGeneration() != before+320 {
		t.Fatal("concurrent clears lost a generation update")
	}
}
