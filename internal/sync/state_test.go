package sync

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNeedsSync(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		hash        string
		want        bool
	}{
		{
			name:        "nil annotations",
			annotations: nil,
			hash:        "abc",
			want:        true,
		},
		{
			name:        "no hash annotation",
			annotations: map[string]string{},
			hash:        "abc",
			want:        true,
		},
		{
			name:        "different hash",
			annotations: map[string]string{AnnotationHash: "old"},
			hash:        "new",
			want:        true,
		},
		{
			name:        "same hash",
			annotations: map[string]string{AnnotationHash: "same"},
			hash:        "same",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations},
			}
			got := NeedsSync(secret, tt.hash)
			if got != tt.want {
				t.Errorf("NeedsSync() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFinalizer(t *testing.T) {
	secret := &corev1.Secret{}

	if HasFinalizer(secret) {
		t.Error("HasFinalizer() = true on new secret")
	}

	AddFinalizer(secret)
	if !HasFinalizer(secret) {
		t.Error("HasFinalizer() = false after AddFinalizer")
	}

	// Adding again should not duplicate
	AddFinalizer(secret)
	count := 0
	for _, f := range secret.Finalizers {
		if f == Finalizer {
			count++
		}
	}
	if count != 1 {
		t.Errorf("finalizer count = %d, want 1", count)
	}

	RemoveFinalizer(secret)
	if HasFinalizer(secret) {
		t.Error("HasFinalizer() = true after RemoveFinalizer")
	}

	// Finalizers should be an empty slice, not nil, to avoid API server conflicts.
	if secret.Finalizers == nil {
		t.Error("Finalizers is nil after RemoveFinalizer, want empty slice")
	}
	if len(secret.Finalizers) != 0 {
		t.Errorf("len(Finalizers) = %d after RemoveFinalizer, want 0", len(secret.Finalizers))
	}
}

func TestUpdateAnnotations(t *testing.T) {
	secret := &corev1.Secret{}
	UpdateAnnotations(UpdateAnnotationsInput{
		Secret:  secret,
		Hash:    "testhash",
		Routers: []string{"r1", "r2"},
	})

	if secret.Annotations[AnnotationHash] != "testhash" {
		t.Errorf("hash = %q, want %q", secret.Annotations[AnnotationHash], "testhash")
	}
	if secret.Annotations[AnnotationRouters] != "r1,r2" {
		t.Errorf("routers = %q, want %q", secret.Annotations[AnnotationRouters], "r1,r2")
	}
	if secret.Annotations[AnnotationTimestamp] == "" {
		t.Error("timestamp is empty")
	}
}

func TestSyncedRouters(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				AnnotationRouters: "r1,r2,r3",
			},
		},
	}

	routers := SyncedRouters(secret)
	if len(routers) != 3 {
		t.Fatalf("len(SyncedRouters) = %d, want 3", len(routers))
	}

	emptySecret := &corev1.Secret{}
	if got := SyncedRouters(emptySecret); got != nil {
		t.Errorf("SyncedRouters on empty secret = %v, want nil", got)
	}
}
