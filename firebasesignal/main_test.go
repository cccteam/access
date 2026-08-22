package firebasesignal

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const emulatorPort = "8080/tcp"

// TestMain starts a Firestore emulator container for the test suite,
// following the db-initiator container pattern used across cccteam repos.
func TestMain(m *testing.M) {
	ctx := context.Background()

	container, host, err := startFirestoreEmulator(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	// The firestore SDK connects to the emulator (unauthenticated, plaintext)
	// whenever this variable is set.
	if err := os.Setenv("FIRESTORE_EMULATOR_HOST", host); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	exitCode := m.Run()

	if err := container.Terminate(ctx); err != nil {
		fmt.Println(err)
	}

	os.Exit(exitCode)
}

func startFirestoreEmulator(ctx context.Context) (testcontainers.Container, string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators",
		Cmd:          []string{"gcloud", "emulators", "firestore", "start", "--host-port=0.0.0.0:8080"},
		WaitingFor:   wait.ForLog("running"),
		ExposedPorts: []string{emulatorPort},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started:          true,
		ContainerRequest: req,
	})
	if err != nil {
		return nil, "", fmt.Errorf("testcontainers.GenericContainer(): %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("testcontainers.Container.Host(): %w", err)
	}
	port, err := container.MappedPort(ctx, emulatorPort)
	if err != nil {
		return nil, "", fmt.Errorf("testcontainers.Container.MappedPort(): %w", err)
	}

	return container, fmt.Sprintf("%s:%s", host, port.Port()), nil
}
